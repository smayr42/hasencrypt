{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TemplateHaskell   #-}

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
  , ChainFetchOptions(..)
  ) where

import           Control.Concurrent        (threadDelay)
import           Control.Lens              as L
import           Control.Monad.Catch
import           Control.Monad.IO.Class
import           Control.Monad.Loops
import           Control.Monad.State       as ST
import           Crypto.Hash               (Digest, SHA256)
import           Crypto.JOSE.JWS           as JWS
import qualified Crypto.PubKey.RSA         as RSA (PrivateKey)
import           Data.Aeson                as A
import qualified Data.Aeson.Lens           as AL
import           Data.Aeson.Types          (parseMaybe)
import qualified Data.ByteString.Char8     as C
import qualified Data.ByteString.Lazy      as L
import qualified Data.HashMap.Strict       as H
import           Data.Text                 as T hiding (filter, map)
import qualified Data.Text.IO              as TIO (writeFile)
import           Data.Text.Strict.Lens
import           Data.X509
import           Data.X509.PKCS10          hiding (subject)
import           Network.HTTP.Types.Status (conflict409, created201)
import           Network.Wreq              as W
import qualified Network.Wreq.Session      as S
import           System.Directory
import           System.FilePath           ((</>))
import           System.Timeout            (timeout)
import           Utils

data ACMEHeader p = ACMEHeader
  { _acmeJwsHeader :: JWSHeader p
  , _acmeJwsNonce  :: Text
  , _acmeJwsUrl    :: Text
  }
makeLenses ''ACMEHeader

instance HasJWSHeader ACMEHeader where
  jwsHeader = acmeJwsHeader

instance HasParams ACMEHeader where
  parseParamsFor prx hp hu
     =  ACMEHeader
    <$> parseParamsFor prx hp hu
    <*> headerRequiredProtected "nonce" hp hu
    <*> headerRequiredProtected "url" hp hu
  params h
    = (True, "nonce" A..= (h ^. acmeJwsNonce))
    : (True, "url" A..= (h ^. acmeJwsUrl))
    : JWS.params (h ^. acmeJwsHeader)
  extensions = const ["nonce"]

acmeJwsAlg :: JWK -> AcmeT s JWS.Alg
acmeJwsAlg jwk' =
  case jwk' ^. jwkMaterial of
    ECKeyMaterial k -> case ecCrv k of
      P_256 -> pure ES256
      P_384 -> pure ES384
      P_521 -> pure ES512
    RSAKeyMaterial _ -> pure RS256
    _ -> throwM $ JWSError "unsupported JWS signing algorithm"

acmeSignedJws :: ToJSON a => JWK -> Text -> Text -> a -> AcmeT s (FlattenedJWS ACMEHeader)
acmeSignedJws jwk' nonce url payload = do
  alg' <- acmeJwsAlg jwk'
  let pubKey = HeaderParam Protected <$> (jwk' ^. asPublicKey)
  let jwsHeader' = newJWSHeader (Protected, alg') & JWS.jwk .~ pubKey
  let jsonPayload = encode payload
  signJWS jsonPayload $ pure (ACMEHeader jwsHeader' nonce url, jwk')

resourceObject :: Text -> Object
resourceObject tp = H.fromList ["resource" A..= tp]

resourceNewReg :: Object
resourceNewReg = resourceObject "new-reg"

resourceReg :: Object
resourceReg = resourceObject "reg"

resourceNewAuthz :: Text -> Object
resourceNewAuthz identifier =
  resourceObject "new-authz" <> H.fromList
    [ "identifier" A..=
      object [ "type" A..= String "dns"
             , "value" A..= identifier
             ]
    ]

resourceChallenge :: Text -> Text -> Object
resourceChallenge tp keyAuthz =
  resourceObject "challenge" <> H.fromList
    [ "type" A..= tp
    , "keyAuthorization" A..= keyAuthz
    ]

resourceNewCert :: Text -> Object
resourceNewCert csr =
  resourceObject "new-cert" <> H.fromList
    [ "csr" A..= csr ]

acmeRequest :: IO (Response a) -> AcmeM (Response a)
acmeRequest request = do
  r <- liftIO request
  acmeNonce L..= (r ^? responseHeader "Replay-Nonce" . utf8)
  return r

acmeSignedPostWith :: ToJSON a => Options -> Text -> a -> AcmeM (Response L.ByteString)
acmeSignedPostWith opts url payload = do
  n <- ensureNonce
  k <- use (acmeKey . to JWS.fromRSA)
  sess <- use acmeSession
  signed <- acmeSignedJws k n url payload
  acmeRequest $ S.postWith opts sess (T.unpack url) $ toJSON signed

acmeSignedPost :: ToJSON a => Text -> a -> AcmeM (Response L.ByteString)
acmeSignedPost = acmeSignedPostWith defaults

useDirectory :: AcmeM Directory
useDirectory = do
  currentDirectory <- use acmeDirectory
  case currentDirectory of
    Nothing -> do
      url <- use acmeDirectoryUrl
      sess <- use acmeSession
      r <- view responseBody <$> (asJSON =<< acmeRequest (S.get sess url))
      acmeDirectory L..= Just r
      return r
    Just dir -> return dir

ensureNonce :: AcmeM Text
ensureNonce = do
  currentNonce <- use acmeNonce
  case currentNonce of
    Nothing -> do
      url <- use acmeDirectoryUrl
      sess <- use acmeSession
      nextNonce <- acmeRequest (S.head_ sess url) >> use acmeNonce
      NonceError "head request did not return nonce" `throwIfNothing` nextNonce
    Just n -> return n

-- perform registration and return the location of the created resource
acmeNewReg :: AcmeM Text
acmeNewReg = do
  let opts = defaults & checkResponse .~ Just statusNewReg
  dir <- useDirectory
  res <- acmeSignedPostWith opts (dir ^. newRegUrl) resourceNewReg
  RegistrationError "registration location missing" `throwIfNothing` (res ^? responseHeader "Location" . utf8)
  where
    statusNewReg _ res
      | res ^. responseStatus == created201 = pure ()
      | res ^. responseStatus == conflict409 = pure ()
      | otherwise = throwM $ RegistrationError (res ^. responseStatus . statusMessage . to C.unpack)

acmeRegUpdate :: Text -> [(Text, Value)] -> AcmeM (Response Object)
acmeRegUpdate url attribs =
  acmeSignedPost url (resourceReg <> H.fromList attribs) >>= asJSON

--agree to the TOS for a specific registration
acmeAgreeTOS :: Text -> AcmeM Object
acmeAgreeTOS reg = do
  resReg <- acmeRegUpdate reg []
  resUpdate <- acmeRegUpdate reg ["agreement" A..= tos resReg]
  return $ resUpdate ^. responseBody
  where
    tos res = res ^? responseLink "rel" "terms-of-service" . linkURL . utf8

-- respond to the http-01 challenge
acmeHttp01Challenge :: FilePath -> Challenge -> AcmeM Challenge
acmeHttp01Challenge webroot challenge = do
  chTypeErr `throwIfNot` (challenge ^. chType == "http-01")
  keyAuthz <- makeKeyAuthz <$> use acmeKey
  do
    liftIO $ TIO.writeFile fileName keyAuthz
    _ <- acmeSignedPost (challenge ^. chUri) $ resourceChallenge "http-01" keyAuthz
    acmeAwaitAuthz (challenge ^. chUri)
  `finally`
    liftIO (removeFile fileName)
  where
    fileName = webroot </> challenge ^. chToken . to unpack
    makeKeyAuthz priv = challenge ^. chToken <> "." <> makeThumbprint priv
    makeThumbprint priv = JWS.fromRSA priv ^. thumbprintSha256 . re digest . base64url . utf8
    thumbprintSha256 = JWS.thumbprint :: Getter JWK (Digest SHA256)
    chTypeErr = AuthorizationError "wrong challenge type"

acmeTimeout :: Int -> AcmeM a -> AcmeM (Maybe a)
acmeTimeout sec (AcmeT f) = do
  s <- ST.get
  res <- liftIO $ timeout usec $ runStateT f s
  case res of
       Just (a,s') -> ST.put s' >> return (Just a)
       Nothing     -> acmeNonce L..= Nothing >> return Nothing
  where
    usec = 1000000 * sec

-- wait until an authorization is valid or revoked
acmeAwaitAuthz :: Text -> AcmeM Challenge
acmeAwaitAuthz url = do
  sess <- use acmeSession
  res <- acmeTimeout 30 $ iterateUntil notPending $ do
    liftIO $ threadDelay $ 1000 * 500
    r <- asJSON =<< liftIO (S.get sess $ T.unpack url)
    return (r ^. responseBody)
  ch <- timeoutErr `throwIfNothing` res
  revokedErr ch `throwIfNot` isValid ch
  return ch
  where
    notPending ch = ch ^. chStatus /= "pending"
    isValid ch = ch ^. chStatus == "valid"
    timeoutErr = AuthorizationError "challenge timed out"
    revokedErr ch =
      AuthorizationError $
        ch ^. chError . _Just . AL.key "detail" . AL._String . to unpack

-- request a new authorization and return the location of the created resource and a list of challenges
-- TODO: handle nontrivial combination policies
-- TODO: respect Retry-After header
-- TODO: investigate whether it's possible to reliabliy reuse existing authorizations
acmeNewAuthz :: Text -> AcmeM (Text, [Challenge])
acmeNewAuthz identifier = do
  dir <- useDirectory
  res <- acmeSignedPost (dir ^. newAuthzUrl) (resourceNewAuthz identifier)
  challenges <- chParseErr `throwIfNothing` parseChallenges res
  loc <- chLocErr `throwIfNothing` (res ^? responseHeader "Location" . utf8)
  return (loc, challenges)
  where
    chParseErr = AuthorizationError "no or invalid challenges received"
    chLocErr = AuthorizationError "challenge location missing"
    parseChallenges res = res ^. responseBody . AL.key "challenges" . to (parseMaybe parseJSON)

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
  sess <- use acmeSession
  responses <- unfoldUntilM (not . hasUpLink) (liftIO .  S.get sess . relUpLink) response
  return $ responses ^.. folded . responseBody
  where
    relUpLink r = r ^. responseLink "rel" "up" . linkURL . utf8 . unpacked
    hasUpLink = has $ responseLink "rel" "up"

data ChainFetchOptions = ChainFull
                       | ChainHead

acmeNewCert :: ChainFetchOptions -> CertificationRequest -> AcmeM CertificateChain
acmeNewCert fetchOpts csr = do
  dict <- useDirectory
  resNew <- acmeSignedPost (dict ^. newCertUrl) (toDER csr ^. base64url . utf8 . to resourceNewCert)
  location <- certLocErr `throwIfNothing` (resNew ^? responseHeader "Location". utf8 . unpacked)
  sess <- use acmeSession
  resCert <- liftIO $ iterateUntilM statusCreated (const $ S.get sess location) resNew
  chain <- throwIfNothing timeoutErr =<< acmeTimeout 30 (fetchChain fetchOpts resCert)
  decodeChain $ CertificateChainRaw $ L.toStrict <$> chain
  where
    fetchChain ChainFull resCert = followUpLinks resCert
    fetchChain ChainHead resCert = return [resCert ^. responseBody]
    statusCreated r = r ^. responseStatus == created201
    certLocErr = AuthorizationError "certificate location missing"
    decodeChain chain = (CertError . show) `throwIfError` decodeCertificateChain chain
    timeoutErr = CertError "timeout when retrieving the certificate chain"

runAcmeM :: RSA.PrivateKey -> String -> AcmeM a -> IO a
runAcmeM accountKey dirUrl (AcmeT m) =
  S.withAPISession $ evalStateT m . initialAcmeState dirUrl accountKey
