{-# LANGUAGE OverloadedStrings #-}

import           ACME
import           Control.Monad            (forM, when)
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
import           Data.Text                hiding (drop, head, length, map)
import           Data.Typeable
import           Data.X509
import           Data.X509.PKCS10         as CSR hiding (subject)
import           Safe
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
  csr <- liftIO $ generateCSR subject extAttrs (privToKeyPair domainPriv) SHA256
  Error `throwIfError` csr
  where
    privToKeyPair priv = KeyPairRSA (private_pub priv) priv
    subject = X520Attributes []
    altNames = map AltNameDNS domains
    extAttrs = PKCS9Attributes [PKCS9Attribute $ ExtSubjectAltName altNames]

retrieveCert :: PrivateKey -> String -> [String] -> AcmeM L.ByteString
retrieveCert domainKey webroot domains = do
    reg <- acmeNewReg
    _ <- acmeAgreeTOS reg
    _ <- forM domains $ acmeNewHttp01Authz webroot . pack
    chain <- makeCSR domainKey domains >>= acmeNewCert
    return $ certChainToPEM chain

main :: IO ()
main = do
  args <- getArgs
  when (length args < 4) $
    getProgName >>= \prog -> die $ "Usage: " ++ prog ++ " webroot account.key domain.key domains..."
  let webroot = head args
  accountKey <- keyFromFile (args !! 1)
  domainKey <- keyFromFile (args !! 2)
  cert <- runAcmeM accountKey $ retrieveCert domainKey webroot (drop 3 args)
  L.putStr cert

