{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards   #-}

import           ACME
import           Control.Monad            (forM, mzero)
import           Control.Monad.Catch      (Exception, MonadThrow)
import           Control.Monad.IO.Class
import           Crypto.Hash
import           Crypto.PubKey.RSA        hiding (Error)
import qualified Crypto.Types.PubKey.RSA  as RSA
import           Data.ASN1.BinaryEncoding
import           Data.ASN1.Encoding
import           Data.ASN1.Types
import qualified Data.ByteString          as B
import qualified Data.ByteString.Char8    as BC
import qualified Data.ByteString.Lazy     as L
import           Data.PEM
import qualified Data.Text                as T
import           Data.Typeable
import           Data.X509
import           Data.X509.PKCS10         as CSR hiding (subject)
import           Safe
import           System.Console.GetOpt
import           System.Environment       (getArgs, getProgName)
import           System.Exit              (die)

decodeDER :: BC.ByteString -> Either String [ASN1]
decodeDER = either (Left . show) Right . decodeASN1' DER

keyFromDER :: BC.ByteString -> Either String RSA.PrivateKey
keyFromDER bs = fst <$> (decodeDER bs >>= fromASN1)

keyFromPEM :: PEM -> Either String RSA.PrivateKey
keyFromPEM pem =
  if pemName pem == "RSA PRIVATE KEY"
  then keyFromDER . pemContent $ pem
  else Left "PEM: unknown format"

-- FIXME: get rid of the deprecated Crypto.PubKey.RSA (crypto-pubkey package)
convPubKey :: RSA.PublicKey -> PublicKey
convPubKey (RSA.PublicKey size n e) = PublicKey size n e

convPrivKey :: RSA.PrivateKey -> PrivateKey
convPrivKey (RSA.PrivateKey pub d p q dP dQ qinv) = PrivateKey (convPubKey pub) d p q dP dQ qinv

data Error = Error String deriving (Show, Typeable)
instance Exception Error

keyFromFile :: (MonadIO m, MonadThrow m) => FilePath -> m PrivateKey
keyFromFile file = do
  bytes <- liftIO $ B.readFile file
  pems <- Error `throwIfError` pemParseBS bytes
  pem <- Error ("pem container '" ++ file ++ "' is empty") `throwIfNothing` headMay pems
  Error `throwIfError` fmap convPrivKey (keyFromPEM pem)

certChainToPEM :: CertificateChain -> L.ByteString
certChainToPEM chain =
  let CertificateChainRaw encoded = encodeCertificateChain chain in
  L.concat $ map certToPEM encoded
  where
    certToPEM bytes = pemWriteLBS $ PEM "CERTIFICATE" [] bytes

makeCSR :: PrivateKey -> [String] -> AcmeM CertificationRequest
makeCSR domainPriv domains = do
  csr <- liftIO $ generateCSR subject extAttrs keyPair SHA256
  Error `throwIfError` csr
  where
    keyPair = KeyPairRSA (private_pub domainPriv) domainPriv
    subject = X520Attributes []
    altNames = map AltNameDNS domains
    extAttrs = PKCS9Attributes [PKCS9Attribute $ ExtSubjectAltName altNames]

retrieveCert :: PrivateKey -> String -> [String] -> AcmeM L.ByteString
retrieveCert domainKey webroot domains = do
    reg <- acmeNewReg
    _ <- acmeAgreeTOS reg
    _ <- forM domains $ acmeNewHttp01Authz webroot . T.pack
    chain <- makeCSR domainKey domains >>= acmeNewCert
    return $ certChainToPEM chain

data Options = Options { optDirectoryUrl :: String
                       , optWebroot      :: String
                       , optAccoutKey    :: String
                       , optDomainKey    :: String
                       , optDomains      :: [String]
                       }

defaultDirectoryUrl :: String
defaultDirectoryUrl = "https://acme-staging.api.letsencrypt.org/directory"

defaultOptions :: Options
defaultOptions = Options defaultDirectoryUrl mzero mzero mzero mzero

options :: [OptDescr (Options -> Options)]
options =
  [ Option ['D'] ["directory-url"]
    (ReqArg
      (\o opts -> opts { optDirectoryUrl = o })
      "URL"
    ) "the ACME directory url"
  , Option ['w'] ["webroot"]
    (ReqArg
      (\o opts -> opts { optWebroot = o })
      "DIR"
    ) "path to webroot for responding to http-01 challenges"
  , Option ['a'] ["account-key"]
    (ReqArg
      (\o opts -> opts { optAccoutKey = o })
      "FILE"
    ) "key for registering the ACME account"
  , Option ['d'] ["domain-key"]
    (ReqArg
      (\o opts -> opts { optDomainKey = o })
      "FILE"
    ) "key for issuing the certificate"
  ]

parseOptions :: [String] -> IO Options
parseOptions args =
  case getOpt Permute options args of
    (opts, domains, []) -> if null domains then
                             getProgName >>= dieWithUsage []
                           else
                             return $ (foldOptions opts) { optDomains = domains }
    (_, _, errs) -> getProgName >>= dieWithUsage (errs ++ ["\n"])
  where
    foldOptions = foldl (flip id) defaultOptions
    dieWithUsage errs prog = die $ concat errs ++ usageInfo (header prog) options
    header :: String -> String
    header prog = "Usage: " ++ prog ++ " [OPTION...] domains...\n"

main :: IO ()
main = do
  Options {..} <- getArgs >>= parseOptions
  accountKey <- keyFromFile $ optAccoutKey
  domainKey <- keyFromFile $ optDomainKey
  cert <- runAcmeM accountKey optDirectoryUrl $ retrieveCert domainKey optWebroot optDomains
  L.putStr cert

