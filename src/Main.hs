{-# LANGUAGE FlexibleContexts      #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE RecordWildCards       #-}

module Main (main) where

import           ACME
import           Control.Monad.Catch
import           Control.Monad.IO.Class
import           Control.Monad.State      as State
import           Crypto.Hash
import           Crypto.PubKey.RSA        hiding (Error)
import           Data.ASN1.BinaryEncoding
import           Data.ASN1.Encoding
import           Data.ASN1.Types
import qualified Data.ByteString          as B
import qualified Data.ByteString.Char8    as Char
import qualified Data.ByteString.Lazy     as L
import           Data.PEM
import qualified Data.Text                as T
import           Data.X509
import           Data.X509.PKCS10         as CSR hiding (subject)
import           PKCS1
import           System.Environment       (getArgs, getProgName)
import           System.Exit              (die)
import           System.IO                (stderr)
import           Text.Printf
import           Utils

decodeDER :: Char.ByteString -> Either String [ASN1]
decodeDER = either (Left . show) Right . decodeASN1' DER

keyFromDER :: Char.ByteString -> Either String PrivateKey
keyFromDER bs = getPrivateKey . fst <$> (decodeDER bs >>= fromASN1)

keyFromPEM :: PEM -> Either String PrivateKey
keyFromPEM pem =
  if pemName pem == "RSA PRIVATE KEY"
  then keyFromDER . pemContent $ pem
  else Left "PEM: unknown format"

data PKCSException = PKCSError String deriving (Show, Typeable)

instance Exception PKCSException where
  displayException (PKCSError e) = "PKCS Error: " ++ e

keyFromFile :: (MonadIO m, MonadThrow m) => FilePath -> m PrivateKey
keyFromFile file = do
  bytes <- liftIO $ B.readFile file
  pems <- PKCSError `throwIfError` pemParseBS bytes
  pem <- PKCSError ("pem container '" ++ file ++ "' is corrupted or empty") `throwIfNothing` headMay pems
  PKCSError `throwIfError` keyFromPEM pem

certChainToPEM :: CertificateChain -> L.ByteString
certChainToPEM chain =
  let CertificateChainRaw encoded = encodeCertificateChain chain in
  L.concat $ certToPEM <$> encoded
  where
    certToPEM bytes = pemWriteLBS $ PEM "CERTIFICATE" [] bytes

makeCSR :: PrivateKey -> [String] -> AcmeM CertificationRequest
makeCSR domainPriv domains = do
  csr <- liftIO $ generateCSR subject extAttrs keyPair SHA256
  PKCSError `throwIfError` csr
  where
    keyPair = KeyPairRSA (private_pub domainPriv) domainPriv
    subject = X520Attributes []
    altNames = AltNameDNS <$> domains
    extAttrs = PKCS9Attributes [PKCS9Attribute $ ExtSubjectAltName altNames]

logStrLn :: (MonadIO m, MonadState Int m, PrintfArg r) => String -> r -> m ()
logStrLn format args = do
  step <- State.get
  liftIO $ hPrintf stderr ("[%v] " ++ format ++ "\n") step args
  State.put $ succ step

retrieveCert :: PrivateKey -> String -> [String] -> AcmeM L.ByteString
retrieveCert domainKey webroot domains =
  flip evalStateT 1 $ do
    regUrl <- lift acmeNewReg
    logStrLn "Registered account with url '%v'" regUrl
    _ <- lift $ acmeAgreeTOS regUrl
    logStrLn "%s" "Agreed to TOS"
    forM_ domains $ \domain -> do
      logStrLn "Performing HTTP validation for domain '%v'..." domain
      _ <- lift $ acmeNewHttp01Authz webroot $ T.pack domain
      logStrLn "Completed challenge for domain '%v'" domain
    chain <- lift (acmeNewCert =<< makeCSR domainKey domains)
    logStrLn "Obtained certificate chain of length %v" (chainLength chain)
    return $ certChainToPEM chain
    where
      chainLength (CertificateChain c) = length c

data Options = Options { optDirectoryUrl :: String
                       , optWebroot      :: String
                       , optAccoutKey    :: String
                       , optDomainKey    :: String
                       , optDomains      :: [String]
                       }

defaultStagingDirectory :: String
defaultStagingDirectory = "https://acme-staging.api.letsencrypt.org/directory"

defaultDirectory :: String
defaultDirectory = "https://acme-v01.api.letsencrypt.org/directory"

defaultOptions :: Options
defaultOptions = Options defaultStagingDirectory mzero mzero mzero mzero

options :: [OptDescrEx (Options -> Options)]
options =
  [ OptOption $ Option ['D'] ["directory-url"]
    (OptArg
      (\o opts -> opts { optDirectoryUrl = fromMaybe defaultDirectory o })
      "URL"
    ) "The ACME directory URL.\n\
      \If no URL is specified, the Let's Encrypt directory is used.\n\
      \For testing purposes this option can be omitted, in which case the\n\
      \Let's Encrypt staging directory is used. Note that certificates\n\
      \issued by the staging environment are not trusted."
  , ReqOption $ Option ['w'] ["webroot"]
    (ReqArg
      (\o opts -> opts { optWebroot = o })
      "DIR"
    ) "Path to the webroot for responding to http challenges."
  , ReqOption $ Option ['a'] ["account-key"]
    (ReqArg
      (\o opts -> opts { optAccoutKey = o })
      "FILE"
    ) "The ACME account key."
  , ReqOption $ Option ['d'] ["domain-key"]
    (ReqArg
      (\o opts -> opts { optDomainKey = o })
      "FILE"
    ) "Key for issuing the certificate."
  ]

parseOptions :: [String] -> IO Options
parseOptions args =
  case getOptReq options args of
    (True, opts, domains, []) -> processOptions opts domains
    (False, _, _, _) -> getProgName >>= dieWithUsage []
    (_, _, _, errs) -> getProgName >>= dieWithUsage (errs ++ ["\n"])
  where
    header :: String -> String
    header prog = "Usage: " ++ prog ++ " [OPTION...] domains...\n"
    dieWithUsage errs prog = die $ concat errs ++ usageInfo (header prog) (getOptDescr <$> options)
    processOptions opts domains =
      if null domains then
        getProgName >>= dieWithUsage []
      else
        return $ (foldl (flip id) defaultOptions opts) { optDomains = domains }

main :: IO ()
main = do
  Options {..} <- parseOptions =<< getArgs
  flip catchAll (die . displayException) $ do
    accountKey <- keyFromFile optAccoutKey
    domainKey <- keyFromFile optDomainKey
    cert <- runAcmeM accountKey optDirectoryUrl $ retrieveCert domainKey optWebroot optDomains
    L.putStr cert

