{-# LANGUAGE FlexibleInstances          #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE OverloadedStrings          #-}
{-# LANGUAGE RecordWildCards            #-}
{-# LANGUAGE ScopedTypeVariables        #-}
{-# LANGUAGE StandaloneDeriving         #-}

module FlatJWS
  ( AlgKey(..)
  , plainJWS
  , PlainJWS
  , signJWS
  , SignedJWS
  , verifyJWS
  , jwkThumbprint
  , getSignedPayload
  ) where

import           Control.Monad              (guard, liftM2, mzero)
import           Crypto.Hash
import           Crypto.PubKey.RSA
import           Crypto.PubKey.RSA.PKCS15   (sign, verify)
import           Data.Aeson                 as JSON
import           Data.Aeson.Types           (parseMaybe)
import           Data.ByteArray             (convert)
import qualified Data.ByteString            as B
import qualified Data.ByteString.Base64.URL as Base64
import qualified Data.ByteString.Char8      as Char
import qualified Data.ByteString.Lazy       as L
import           Data.Functor.Identity
import qualified Data.HashMap.Strict        as H
import           Data.Maybe                 (fromMaybe)
import           Data.Monoid                ((<>))
import           Data.String                (IsString)
import           Data.Text                  (Text)
import           Data.Text.Encoding         (decodeUtf8, encodeUtf8)
import           Data.Tuple                 (swap)

newtype ByteString64 = ByteString64 { getByteString :: B.ByteString }
  deriving (Monoid, IsString, Show)

class ToBase64 a where
  toBase64 :: a -> ByteString64

class FromBase64 a where
  fromBase64 :: ByteString64 -> a

decode64 :: ByteString64 -> Char.ByteString
decode64 (ByteString64 bs)  = Base64.decodeLenient bs

encode64 :: Char.ByteString -> ByteString64
encode64 = ByteString64 . fst . Char.spanEnd (== '=') . Base64.encode

instance ToBase64 B.ByteString where
  toBase64 = encode64

instance FromBase64 B.ByteString where
  fromBase64 = decode64

instance ToBase64 L.ByteString where
  toBase64 = encode64 . L.toStrict

instance FromBase64 L.ByteString where
  fromBase64 = L.fromStrict . decode64

instance ToJSON ByteString64 where
  toJSON = toJSON . decodeUtf8 . getByteString

instance FromJSON ByteString64 where
  parseJSON (String s) = pure . ByteString64 . encodeUtf8 $ s
  parseJSON _ = mzero

instance ToBase64 Object where
  toBase64 = toBase64 . JSON.encode

bsToInteger :: B.ByteString -> Integer
bsToInteger = B.foldl (\acc x -> acc * 256 + toInteger x) 0

integerToBS :: Integer -> B.ByteString
integerToBS = B.reverse . B.unfoldr (fmap swap <$> gen)
  where
    gen x = if x == 0 then Nothing else Just (fromIntegral <$> quotRem x 256)

instance ToBase64 Integer where
  toBase64 = encode64 . integerToBS

instance FromBase64 Integer where
  fromBase64 = bsToInteger . decode64

data B64Data a = B64Data { getB64 :: ByteString64, getData :: a }
  deriving (Show)

encodeB64Data :: ToBase64 a => a -> B64Data a
encodeB64Data x = B64Data (toBase64 x) x

instance ToJSON (B64Data a) where
  toJSON = toJSON . getB64

instance FromJSON a => FromJSON (B64Data a) where
  parseJSON v = do
    bs64 <- parseJSON v
    B64Data bs64 <$> jsonDecode (fromBase64 bs64)
    where
      jsonDecode x = maybe mzero pure $ JSON.decode x

data JWS d a = JWS
  { payload   :: d a
  , protected :: Maybe (d Object)
  , header    :: Maybe Object
  }

deriving instance Show a => Show (JWS B64Data a)

type PlainJWS a = JWS Identity a

deriving instance Show a => Show (PlainJWS a)

plainJWS :: a -> Maybe Object -> Maybe Object -> PlainJWS a
plainJWS payload protected =
  JWS (Identity payload) (Identity <$> protected)

data SignedJWS a = SignedJWS
  { jws       :: JWS B64Data a
  , signature :: B.ByteString
  } deriving (Show)

getSignedPayload :: SignedJWS c -> c
getSignedPayload SignedJWS{..} = getData . payload $ jws

data AlgKey = RS256 { getPrivateKey :: PrivateKey }

rs256AlgParam :: Text
rs256AlgParam = "RS256"

rsaKtyParam :: Text
rsaKtyParam = "RSA"

algToObject :: AlgKey -> Object
algToObject (RS256 key) =
  H.fromList
  [ "alg" .= rs256AlgParam
  , "jwk" .= object
    [ "kty" .= rsaKtyParam
    , "n" .= toBase64 (public_n pubKey)
    , "e" .= toBase64 (public_e pubKey)
    , "alg" .= rs256AlgParam
    ]
  ]
  where pubKey = private_pub key

objectToAlg :: Object -> Maybe AlgKey
objectToAlg = parseMaybe $ \o -> do
  alg <- o .: "alg"
  guard $ alg == rs256AlgParam
  jwk <- o .: "jwk"
  kty <- jwk .: "kty"
  guard $ kty == rsaKtyParam
  e <- fromBase64 . ByteString64 . encodeUtf8 <$> jwk .: "e"
  bytesN <- fromBase64 . ByteString64 . encodeUtf8 <$> jwk .: "n"
  let (size, n) = (B.length bytesN, bsToInteger bytesN)
  return $ RS256 $ PrivateKey (PublicKey size n e) 0 0 0 0 0 0

instance ToJSON AlgKey where
  toJSON = Object . algToObject

instance FromJSON AlgKey where
  parseJSON (Object o) = maybe mzero pure $ objectToAlg o
  parseJSON _ = mzero

instance ToBase64 a => ToJSON (SignedJWS a) where
  toJSON SignedJWS{..} =
    let JWS{..} = jws in
      object $
      [ "payload" .= payload
      , "signature" .= toBase64 signature
      ]
      ++ maybeValue "protected" protected
      ++ maybeValue "header" header
      where
        maybeValue key = maybe [] (\v -> [ key .= v])

instance FromJSON a => FromJSON (JWS B64Data a) where
  parseJSON (Object v) =
    JWS <$> v .: "payload"
        <*> v .:? "protected"
        <*> v .:? "header"
  parseJSON _ = mzero

instance FromJSON a => FromJSON (SignedJWS a) where
  parseJSON v@(Object o) =
    SignedJWS <$> parseJSON v
              <*> (fromBase64 <$> o .: "signature")
  parseJSON _ = mzero

-- FIXME: switch to cryptonite and use signSafer
signJWS :: ToBase64 a => AlgKey -> PlainJWS a -> Either Error (SignedJWS a)
signJWS alg@(RS256 key) JWS{..} =
  SignedJWS jws <$> signature
  where
    jws = JWS payloadB64 (Just protectedB64) header
    signature = sign Nothing (Just SHA256) key $ getByteString input
    input = getB64 protectedB64 <> "." <> getB64 payloadB64
    payloadB64 = encodeB64Data . runIdentity $ payload
    protectedB64 = encodeB64Data protectedAlg
    protectedAlg = algToObject alg <> protectedObj
    protectedObj = fromMaybe H.empty $ runIdentity <$> protected

signedJWSAlgKey :: SignedJWS t -> Maybe AlgKey
signedJWSAlgKey SignedJWS{..} =
  headers >>= objectToAlg
  where
    headers = liftM2 (<>) (getData <$> protected) header
    JWS{..} = jws

signingInput :: SignedJWS a -> Char.ByteString
signingInput SignedJWS{..} =
  getByteString $ protectedB64 <> "." <> getB64 payload
  where
    protectedB64 =  fromMaybe "" $ getB64 <$> protected
    JWS{..} = jws

verifyJWS :: SignedJWS a -> Bool
verifyJWS jws =
  case signedJWSAlgKey jws of
    Nothing -> False
    Just algKey ->
      verify (Just SHA256) key input $ signature jws
        where key = private_pub $ getPrivateKey algKey
              input = signingInput jws

jwkThumbprint :: forall a. HashAlgorithm a => a -> PublicKey -> Text
jwkThumbprint _ PublicKey{..} =
  let input = "{\"e\":\"" <>
              toBase64 public_e <>
              "\",\"kty\":\"RSA\",\"n\":\"" <>
              toBase64 public_n <>
              "\"}"
      h = hash (getByteString input) :: Digest a
      bs = convert h :: B.ByteString
  in decodeUtf8 . getByteString . toBase64 $ bs

