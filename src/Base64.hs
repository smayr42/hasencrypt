{-# LANGUAGE FlexibleInstances          #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}

module Base64
  ( ByteString64(..)
  , toBase64
  , fromBase64
  , encodeUnpad64
  , decode64
  , ToBase64
  , FromBase64
  ) where

import           Data.Aeson                 as JSON
import qualified Data.ByteString            as B
import qualified Data.ByteString.Base64.URL as Base64
import qualified Data.ByteString.Char8      as Char
import qualified Data.ByteString.Lazy       as L
import           Utils

newtype ByteString64 = ByteString64 { getByteString :: B.ByteString }
  deriving (Monoid, IsString, Show)

class ToBase64 a where
  toBase64 :: a -> ByteString64

class FromBase64 a where
  fromBase64 :: ByteString64 -> a

decode64 :: ByteString64 -> Char.ByteString
decode64 (ByteString64 bs)  = Base64.decodeLenient bs

encodeUnpad64 :: Char.ByteString -> ByteString64
encodeUnpad64 = ByteString64 . fst . Char.spanEnd (== '=') . Base64.encode

instance ToBase64 B.ByteString where
  toBase64 = encodeUnpad64

instance FromBase64 B.ByteString where
  fromBase64 = decode64

instance ToBase64 L.ByteString where
  toBase64 = encodeUnpad64 . L.toStrict

instance FromBase64 L.ByteString where
  fromBase64 = L.fromStrict . decode64

instance ToJSON ByteString64 where
  toJSON = toJSON . decodeUtf8 . getByteString

instance FromJSON ByteString64 where
  parseJSON (String s) = pure . ByteString64 . encodeUtf8 $ s
  parseJSON _ = mzero

instance ToBase64 Object where
  toBase64 = toBase64 . JSON.encode

instance ToBase64 Integer where
  toBase64 = encodeUnpad64 . integerToBS

instance FromBase64 Integer where
  fromBase64 = bsToInteger . decode64

