{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE OverloadedStrings          #-}
{-# LANGUAGE Rank2Types                 #-}
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
  ) where

import           Base64
import           Control.Concurrent        (threadDelay)
import           Control.Lens              as Lens
import           Control.Monad.Catch
import           Control.Monad.IO.Class
import           Control.Monad.Loops
import           Control.Monad.State       as State
import           Crypto.Hash               as Hash
import           Crypto.PubKey.RSA         (PrivateKey, private_pub)
import           Crypto.PubKey.RSA.Types   (Error)
import           Crypto.Random.Types
import           Data.Aeson                as JSON
import qualified Data.Aeson.Lens           as JLens
import           Data.Aeson.Types          (parseMaybe)
import qualified Data.ByteString.Lazy      as L
import qualified Data.HashMap.Strict       as H
import           Data.Text                 as Text hiding (filter, map)
import qualified Data.Text.IO              as TextIO (writeFile)
import           Data.X509
import           Data.X509.PKCS10          hiding (subject)
import           FlatJWS
import           Network.HTTP.Client       (HttpException (..))
import           Network.HTTP.Types.Header (HeaderName)
import           Network.HTTP.Types.Status (conflict409, created201)
import           Network.Wreq              as Wreq
import           System.Directory
import           System.FilePath           ((</>))
import           System.Timeout            (timeout)
import           Utils

responseHeaderUtf8 :: HeaderName -> Fold (Response body) Text
responseHeaderUtf8 name = responseHeader name . to decodeUtf8
responseHeaderString :: HeaderName -> Fold (Response body) String
responseHeaderString name = responseHeaderUtf8 name . to unpack

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
  , _chError  :: Maybe Value
  } deriving (Eq, Show)
makeLenses ''Challenge

instance FromJSON Challenge where
  parseJSON (Object o) =
    Challenge <$> o .: "type"
              <*> o .: "uri"
              <*> o .: "token"
              <*> o .: "status"
              <*> o .:? "error"
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

instance Exception AcmeException where
  displayException (RSAError e)           = "RSA error: " ++ show e
  displayException (NonceError e)         = "Nonce error: " ++ e
  displayException (RegistrationError e)  = "Registration error: " ++ e
  displayException (AuthorizationError e) = "Authorization error: " ++ e
  displayException (JWSError e)           = "JWS error: " ++ e
  displayException (CertError e)          = "Certificate error: " ++ e

newtype AcmeT s a = AcmeT { _runAcmeT :: StateT s IO a }
  deriving (Functor, Applicative, Monad, MonadIO, MonadThrow, MonadCatch, MonadMask, MonadState s)

type AcmeM a = AcmeT AcmeState a

instance MonadRandom (AcmeT s) where
  getRandomBytes = liftIO . getRandomBytes

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


acmeRequest :: IO (Response a) -> AcmeM (Response a)
acmeRequest request = do
  r <- liftIO request
  nonce Lens..= (r ^? responseHeaderUtf8 "Replay-Nonce")
  return r

acmeSignedPostWith :: ToJSON a => Options -> String -> a -> AcmeM (Response L.ByteString)
acmeSignedPostWith opts url payload = do
  n <- ensureNonce
  k <- use key
  signed <- throwIfError RSAError =<< signJWS (RS256 k) (makeJWS n)
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
      r <- (^. responseBody) <$> (asJSON =<< acmeRequest (Wreq.get url))
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

-- perform registration and return the location of the created resource
acmeNewReg :: AcmeM Text
acmeNewReg = do
  let opts = Wreq.defaults & Wreq.checkStatus .~ Just statusNewReg
  url <- unpack . newRegUrl <$> ensureDirectory
  res <- acmeSignedPostWith opts url resourceNewReg
  RegistrationError "registration location missing" `throwIfNothing` (res ^? responseHeaderUtf8 "Location")
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
  do
    liftIO $ TextIO.writeFile fileName keyAuthz
    _ <- acmeSignedPost uri $ resourceChallenge "http-01" keyAuthz
    acmeAwaitAuthz uri
  `finally`
    liftIO (removeFile fileName)
  where
    fileName = webroot </> challenge ^. chToken . to unpack
    uri = challenge ^. chUri . to unpack
    makeKeyAuthz priv = challenge ^. chToken <> "." <> makeThumbprint priv
    makeThumbprint priv = jwkThumbprint Hash.SHA256 (private_pub priv)
    chTypeErr = AuthorizationError "wrong challenge type"

acmeTimeout :: Int -> AcmeM a -> AcmeM (Maybe a)
acmeTimeout sec (AcmeT f) = do
  s <- State.get
  res <- liftIO $ timeout usec $ runStateT f s
  case res of
       Just (a,s') -> State.put s' >> return (Just a)
       Nothing     -> nonce Lens..= Nothing >> return Nothing
  where
    usec = 1000000 * sec

-- wait until an authorization is valid or revoked
acmeAwaitAuthz :: String -> AcmeM Challenge
acmeAwaitAuthz url = do
  res <- acmeTimeout 30 $ iterateUntil notPending $ do
    liftIO $ threadDelay $ 1000 * 500
    fmap (^. responseBody) . asJSON =<< liftIO (Wreq.get url)
  ch <- timeoutErr `throwIfNothing` res
  revokedErr ch `throwIfNot` isValid ch
  return ch
  where
    notPending ch = ch ^. chStatus /= "pending"
    isValid ch = ch ^. chStatus == "valid"
    timeoutErr = AuthorizationError "challenge timed out"
    revokedErr ch =
      AuthorizationError $
        ch ^. chError . _Just . JLens.key "detail" . JLens._String . to unpack

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

followUpLinks :: Response L.ByteString -> AcmeM [L.ByteString]
followUpLinks response = do
  responses <- unfoldUntilM (not . hasUpLink) (liftIO .  Wreq.get . relUpLink) response
  return $ responses ^.. folded . responseBody
  where
    relUpLink r = r ^. responseLink "rel" "up" . linkURL . to decodeUtf8 . to unpack
    hasUpLink = has $ responseLink "rel" "up"

-- request a new certificate and return it as the head of a (hopefully complete) certificate chain
acmeNewCert :: CertificationRequest -> AcmeM CertificateChain
acmeNewCert csr = do
  url <- unpack . newCertUrl <$> ensureDirectory
  resNew <- acmeSignedPost url $ resourceNewCert $ base64 $ toDER csr
  location <- certLocErr `throwIfNothing` (resNew ^? responseHeaderString "Location")
  resCert <- liftIO $ iterateUntilM statusCreated (const $ Wreq.get location) resNew
  chain <- throwIfNothing timeoutErr =<< acmeTimeout 30 (followUpLinks resCert)
  decodeChain $ CertificateChainRaw $ L.toStrict <$> chain
  where
    base64 = decodeUtf8 . getByteString . encodeUnpad64
    statusCreated r = r ^. responseStatus == created201
    certLocErr = AuthorizationError "certificate location missing"
    decodeChain chain = (CertError . show) `throwIfError` decodeCertificateChain chain
    timeoutErr = CertError "timeout when retrieving the certificate chain"

runAcmeM :: PrivateKey -> String -> AcmeM a -> IO a
runAcmeM accountKey dirUrl (AcmeT m) = evalStateT m $ initialAcmeState accountKey dirUrl

