{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE OverloadedStrings          #-}
{-# LANGUAGE TemplateHaskell            #-}

module ACME
  ( AcmeM
  , runAcmeM
  , acmeNewReg
  , acmeAgreeTOS
  , acmeNewAuthz
  , acmeNewHttp01Authz
  , acmeHttp01Challenge
  , acmeNewCert
  , chType
  , chUri
  , chToken
  , chStatus
  , throwIfNot
  , throwIfNothing
  , throwIfError
  ) where

import           Control.Concurrent         (threadDelay)
import           Control.Lens               as Lens
import           Control.Monad.Catch
import           Control.Monad.IO.Class
import           Control.Monad.Loops
import           Control.Monad.State        hiding (get)
import           Crypto.Hash                as Hash
import           Crypto.PubKey.RSA          (PrivateKey, private_pub)
import           Crypto.PubKey.RSA.Types    (Error)
import           Data.Aeson                 as JSON
import qualified Data.Aeson.Lens            as JLens
import           Data.Aeson.Types           (parseMaybe)
import qualified Data.ByteString.Base64.URL as Base64
import qualified Data.ByteString.Char8      as Char
import qualified Data.ByteString.Lazy       as L
import qualified Data.HashMap.Strict        as H
import           Data.Monoid                ((<>))
import           Data.Text                  hiding (filter, map)
import           Data.Text.Encoding         (decodeUtf8)
import qualified Data.Text.IO               as TextIO (writeFile)
import           Data.Typeable
import           Data.X509
import           Data.X509.PKCS10           hiding (subject)
import           FlatJWS
import           Network.HTTP.Client        (HttpException (..))
import           Network.HTTP.Types.Header  (HeaderName)
import           Network.HTTP.Types.Status  (conflict409, created201)
import           Network.Wreq               as Wreq
import           Safe
import           System.FilePath            ((</>))
import           System.IO                  (hPrint, stderr)

data Directory = Directory
  { newRegUrl      :: Text
  , newAuthzUrl    :: Text
  , newCertUrl     :: Text
  , _revokeCertUrl :: Text
  } deriving (Eq, Show)

instance FromJSON Directory where
  parseJSON (Object o) =
    Directory <$> o .: "new-reg"
              <*> o .: "new-authz"
              <*> o .: "new-cert"
              <*> o .: "revoke-cert"
  parseJSON _ = mzero

data Challenge = Challenge
  { _chType   :: Text
  , _chUri    :: Text
  , _chToken  :: Text
  , _chStatus :: Text
  } deriving (Eq, Show)
makeLenses ''Challenge

instance FromJSON Challenge where
  parseJSON (Object o) =
    Challenge <$> o.: "type"
              <*> o.: "uri"
              <*> o.: "token"
              <*> o.: "status"
  parseJSON _ = mzero

data AcmeState = AcmeState
  { _nonce        :: Maybe Text
  , _directory    :: Maybe Directory
  , _key          :: PrivateKey
  , _directoryUrl :: String
  } deriving Show
makeLenses ''AcmeState

initialAcmeState :: PrivateKey -> String -> AcmeState
initialAcmeState = AcmeState Nothing Nothing

data AcmeException =
    RSAError Error
  | NonceError String
  | RegistrationError String
  | AuthorizationError String
  | JWSError String
  | CertError String
  deriving (Show, Typeable)

instance Exception AcmeException

throwIfNot :: (MonadThrow m, Exception e) => e -> Bool -> m ()
throwIfNot e b = if not b then throwM e else pure ()

throwIfNothing :: (MonadThrow m, Exception e) => e -> Maybe a -> m a
throwIfNothing e = maybe (throwM e) pure

throwIfError :: (MonadThrow m, Exception e) => (a -> e) -> Either a b -> m b
throwIfError f = either (throwM . f) pure

responseHeaderUtf8 :: (Applicative f, Contravariant f) => HeaderName -> (Text -> f Text) -> Response body -> f (Response body)
responseHeaderUtf8 name = responseHeader name . to decodeUtf8
responseHeaderString :: (Applicative f, Contravariant f) => HeaderName -> (String -> f String) -> Response body -> f (Response body)
responseHeaderString name = responseHeaderUtf8 name . to unpack

newtype AcmeT s a = AcmeT { _runAcmeT :: StateT s IO a }
  deriving (Functor, Applicative, Monad, MonadIO, MonadThrow, MonadState s)

type AcmeM a = AcmeT AcmeState a

-- TODO: implement proper logging
dbgPrint :: Show a => a -> AcmeM ()
dbgPrint = liftIO . hPrint stderr . show

acmeRequest :: IO (Response a) -> AcmeM (Response a)
acmeRequest request = do
  r <- liftIO request
  nonce Lens..= (r ^? responseHeaderUtf8 "Replay-Nonce")
  return r

acmeSignedPostWith :: ToJSON a => Options -> String -> a -> AcmeM (Response L.ByteString)
acmeSignedPostWith opts url payload = do
  n <- ensureNonce
  k <- use key
  signed <- RSAError `throwIfError` signJWS (RS256 k) (makeJWS n)
  acmeRequest $ postWith opts url $ toJSON signed
  where
    makeJWS n = plainJWS (encode payload) (Just $ makeHeader n) Nothing
    makeHeader n = H.fromList [("nonce", String n)]

acmeSignedPost :: ToJSON a => String -> a -> AcmeM (Response L.ByteString)
acmeSignedPost = acmeSignedPostWith Wreq.defaults

ensureDirectory :: AcmeM Directory
ensureDirectory = do
  currentDirectory <- use directory
  case currentDirectory of
    Nothing -> do
      url <- use directoryUrl
      r <- (^. responseBody) <$> (asJSON =<< acmeRequest (get url))
      directory Lens..= Just r
      return r
    Just dir -> return dir

ensureNonce :: AcmeM Text
ensureNonce = do
  currentNonce <- use nonce
  case currentNonce of
    Nothing -> do
      url <- use directoryUrl
      nextNonce <- acmeRequest (head_ url) >> use nonce
      NonceError "head request did not return nonce" `throwIfNothing` nextNonce
    Just n -> return n

resourceObject :: Text -> Object
resourceObject tp = H.fromList ["resource" JSON..= tp]

resourceNewReg :: Object
resourceNewReg = resourceObject "new-reg"

resourceReg :: Object
resourceReg = resourceObject "reg"

resourceNewAuthz :: Text -> Object
resourceNewAuthz identifier =
  resourceObject "new-authz" <> H.fromList
    [ "identifier" JSON..=
      object [ "type" JSON..= String "dns"
             , "value" JSON..= identifier
             ]
    ]

resourceChallenge :: Text -> Text -> Object
resourceChallenge tp keyAuthz =
  resourceObject "challenge" <> H.fromList
    [ "type" JSON..= tp
    , "keyAuthorization" JSON..= keyAuthz
    ]

resourceNewCert :: Text -> Object
resourceNewCert csr =
  resourceObject "new-cert" <> H.fromList
    [ "csr" JSON..= csr ]

-- parse and verify a response containing a JWS with JSON payload
_asSignedJWS :: FromJSON a => Response L.ByteString -> AcmeM (SignedJWS a)
_asSignedJWS response = do
  jws <- (^. responseBody) <$> asJSON response
  JWSError "invalid JWS signature" `throwIfNot` verifyJWS jws
  return jws

-- perform registration and return the location of the created resource
acmeNewReg :: AcmeM Text
acmeNewReg = do
  let opts = Wreq.defaults & Wreq.checkStatus .~ Just statusNewReg
  url <- unpack . newRegUrl <$> ensureDirectory
  res <- acmeSignedPostWith opts url resourceNewReg
  loc <- RegistrationError "registration location missing" `throwIfNothing` (res ^? responseHeaderUtf8 "Location")
  dbgPrint $ "Registration: " <> loc
  return loc
  where
    statusNewReg s h c
      | s == created201 = Nothing
      | s == conflict409 = Nothing
      | otherwise = Just . toException . StatusCodeException s h $ c

--agree to the TOS for a specific registration
acmeAgreeTOS :: Text -> AcmeM Object
acmeAgreeTOS reg = do
  resReg <- acmeRegUpdate sreg []
  resUpdate <- acmeRegUpdate sreg ["agreement" JSON..= tos resReg]
  return $ resUpdate ^. responseBody
  where
    sreg = unpack reg
    acmeRegUpdate :: String -> [(Text, Value)] -> AcmeM (Response Object)
    acmeRegUpdate url attribs = acmeSignedPost url (resourceReg <> H.fromList attribs) >>= asJSON
    tos res = res ^? responseLink "rel" "terms-of-service" . linkURL . to decodeUtf8

-- respond to the http-01 challenge
acmeHttp01Challenge :: FilePath -> Challenge -> AcmeM Challenge
acmeHttp01Challenge webroot challenge = do
  chTypeErr `throwIfNot` (challenge ^. chType == "http-01")
  keyAuthz <- makeKeyAuthz <$> use key
  liftIO $ TextIO.writeFile (webroot </> challenge ^. chToken . to unpack) keyAuthz
  _ <- acmeSignedPost uri $ resourceChallenge "http-01" keyAuthz
  acmeAwaitAuthz uri
  where
    uri = challenge ^. chUri . to unpack
    makeKeyAuthz priv = challenge ^. chToken <> "." <> makeThumbprint priv
    makeThumbprint priv = jwkThumbprint Hash.SHA256 (private_pub priv)
    chTypeErr = AuthorizationError "wrong challenge type"

-- wait until an authorization is valid or revoked
-- TODO: add (configurable?) timeout
acmeAwaitAuthz :: String -> AcmeM Challenge
acmeAwaitAuthz url =
  iterateUntil notPending $ do
    liftIO $ threadDelay $ 1000 * 500
    challenge <- fmap (^. responseBody) . asJSON =<< liftIO (get url)
    dbgPrint $ "Status: " <> challenge ^. chStatus
    return challenge
  where
    notPending challenge = challenge ^. chStatus /= "pending"

-- request a new authorization and return the location of the created resource and a list of challenges
-- TODO: handle nontrivial combination policies
-- TODO: respect Retry-After header
-- TODO: investigate whether it's possible to reliabliy reuse existing authorizations
acmeNewAuthz :: Text -> AcmeM (Text, [Challenge])
acmeNewAuthz identifier = do
  url <- unpack . newAuthzUrl <$> ensureDirectory
  res <- acmeSignedPost url $ resourceNewAuthz identifier
  challenges <- chParseErr `throwIfNothing` parseChallenges res
  loc <- chLocErr `throwIfNothing` (res ^? responseHeaderUtf8 "Location")
  return (loc, challenges)
  where
    chParseErr = AuthorizationError "no or invalid challenges received"
    chLocErr = AuthorizationError "challenge location missing"
    parseChallenges res = res ^. responseBody . JLens.key "challenges" . to (parseMaybe parseJSON)

-- authorize a new domain by responding to the http-01 challenge
acmeNewHttp01Authz :: FilePath -> Text -> AcmeM Challenge
acmeNewHttp01Authz webroot domain = do
  (_, challenges) <- acmeNewAuthz domain
  challenge <- noChallengeError `throwIfNothing` headMay (filter isHttp01 challenges)
  acmeHttp01Challenge webroot challenge
  where
    noChallengeError = AuthorizationError "no http-01 challenge"
    isHttp01 ch = ch ^. chType . to (== "http-01")

-- FIXME: similar definition in FlatJWS
encode64 :: Char.ByteString -> Text
encode64 = decodeUtf8 . fst . Char.spanEnd (== '=') . Base64.encode

unfoldUntilM :: (Monad m) => (a -> Bool) -> (a -> m a) -> a -> m [a]
unfoldUntilM p f v
    | p v       = return [v]
    | otherwise = f v >>= \v' -> (v:) <$> unfoldUntilM p f v'

-- TODO: limit the number of followed links
followUpLinks :: Response L.ByteString -> AcmeM [L.ByteString]
followUpLinks response = do
  responses <- unfoldUntilM (not . hasUpLink) (liftIO .  get . relUpLink) response
  return $ responses ^.. folded . responseBody
  where
    relUpLink r = r ^. responseLink "rel" "up" . linkURL . to decodeUtf8 . to unpack
    hasUpLink = has $ responseLink "rel" "up"

-- request a new certificate and return it as the head of a (hopefully complete) certificate chain
acmeNewCert :: CertificationRequest -> AcmeM CertificateChain
acmeNewCert csr = do
  url <- unpack . newCertUrl <$> ensureDirectory
  resNew <- acmeSignedPost url $ resourceNewCert $ encode64 $ toDER csr
  location <- certLocErr `throwIfNothing` (resNew ^? responseHeaderString "Location")
  resCert <- liftIO $ iterateUntilM statusCreated (const $ get location) resNew
  chain <- followUpLinks resCert
  decodeChain $ CertificateChainRaw $ map L.toStrict chain
  where
    statusCreated r = r ^. responseStatus == created201
    certLocErr = AuthorizationError "certification location missing"
    decodeChain chain = (CertError . show) `throwIfError` decodeCertificateChain chain

runAcmeM :: PrivateKey -> String -> AcmeM a -> IO a
runAcmeM accountKey dirUrl (AcmeT m) = evalStateT m $ initialAcmeState accountKey dirUrl

