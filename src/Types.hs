{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE MultiParamTypeClasses      #-}
{-# LANGUAGE OverloadedStrings          #-}
{-# LANGUAGE TemplateHaskell            #-}

module Types where

import           Control.Lens              (makeClassyPrisms, makeLenses)
import           Control.Monad             (mzero)
import           Control.Monad.Catch
import           Control.Monad.Error.Class (MonadError, catchError, throwError)
import           Control.Monad.IO.Class    (MonadIO, liftIO)
import           Control.Monad.State       (StateT)
import           Control.Monad.State.Class (MonadState)
import qualified Crypto.JOSE.Error         as JOSE (AsError (..), Error)
import qualified Crypto.PubKey.RSA.Types   as RSA (Error, PrivateKey)
import           Crypto.Random.Types       (MonadRandom, getRandomBytes)
import           Data.Aeson
import           Data.Text                 (Text)
import           Data.Typeable             (Typeable)
import           Network.Wreq.Session      (Session)

data Directory = Directory
  { _newRegUrl     :: Text
  , _newAuthzUrl   :: Text
  , _newCertUrl    :: Text
  , _revokeCertUrl :: Text
  } deriving (Eq, Show)
makeLenses ''Directory

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
  { _acmeNonce        :: Maybe Text
  , _acmeDirectory    :: Maybe Directory
  , _acmeDirectoryUrl :: String
  , _acmeKey          :: RSA.PrivateKey
  , _acmeSession      :: Session
  } deriving Show
makeLenses ''AcmeState

initialAcmeState :: String -> RSA.PrivateKey -> Session -> AcmeState
initialAcmeState = AcmeState Nothing Nothing

data AcmeException =
    RSAError RSA.Error
  | NonceError String
  | RegistrationError String
  | AuthorizationError String
  | JWSError String
  | JWSError' JOSE.Error
  | CertError String
  deriving (Show, Typeable)
makeClassyPrisms ''AcmeException

instance Exception AcmeException where
  displayException (RSAError e)           = "RSA error: " ++ show e
  displayException (NonceError e)         = "Nonce error: " ++ e
  displayException (RegistrationError e)  = "Registration error: " ++ e
  displayException (AuthorizationError e) = "Authorization error: " ++ e
  displayException (JWSError e)           = "JWS error: " ++ e
  displayException (JWSError' e)          = "JWS error: " ++ show e
  displayException (CertError e)          = "Certificate error: " ++ e

instance JOSE.AsError AcmeException where
  _Error = _JWSError'

newtype AcmeT s a = AcmeT { _runAcmeT :: StateT s IO a }
  deriving (Functor, Applicative, Monad, MonadIO, MonadThrow, MonadCatch, MonadMask, MonadState s)

type AcmeM a = AcmeT AcmeState a

instance MonadRandom (AcmeT s) where
  getRandomBytes = liftIO . getRandomBytes

instance MonadError AcmeException (AcmeT s) where
  throwError = throwM
  catchError = catch
