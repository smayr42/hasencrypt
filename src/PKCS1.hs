module PKCS1
  ( PKCS1PubKey(..)
  , PKCS1PrivKey(..)
  ) where

-- Read/Write RSA keys that are ASN1-encoded according to PKCS1.
-- Mostly adapted from Vincent Hanquez's crypto-pubkey-types package.

import           Crypto.PubKey.RSA
import           Data.ASN1.BinaryEncoding (BER (BER))
import           Data.ASN1.Encoding       (decodeASN1')
import           Data.ASN1.Types

newtype PKCS1PubKey = PKCS1PubKey { getPublicKey :: PublicKey }
newtype PKCS1PrivKey = PKCS1PrivKey { getPrivateKey :: PrivateKey }

instance ASN1Object PKCS1PubKey where
  toASN1 (PKCS1PubKey pubKey) xs =
    Start Sequence
    : IntVal (public_n pubKey)
    : IntVal (public_e pubKey)
    : End Sequence
    : xs

  fromASN1 ( Start Sequence
           : IntVal modulus
           : IntVal pubexp
           : End Sequence:xs
           ) =
    Right
      ( PKCS1PubKey
          PublicKey { public_size = calculate_modulus modulus 1
                    , public_n    = modulus
                    , public_e    = pubexp
                    }
      , xs)
      where
        calculate_modulus n i = if (2 ^ (i * 8)) > n then i else calculate_modulus n (i+1)

  fromASN1 ( Start Sequence
           : IntVal 0
           : Start Sequence
           : OID [1, 2, 840, 113549, 1, 1, 1]
           : Null
           : End Sequence
           : OctetString bs
           : xs
           ) =
    let inner = either strError fromASN1 $ decodeASN1' BER bs
        strError = Left . ("fromASN1: RSA.PublicKey: " ++) . show
    in either Left (\(k, _) -> Right (k, xs)) inner

  fromASN1 _ =
    Left "fromASN1: RSA.PublicKey: unexpected format"

instance ASN1Object PKCS1PrivKey where
  toASN1 (PKCS1PrivKey privKey) xs =
      Start Sequence
    : IntVal 0
    : IntVal (public_n $ private_pub privKey)
    : IntVal (public_e $ private_pub privKey)
    : IntVal (private_d privKey)
    : IntVal (private_p privKey)
    : IntVal (private_q privKey)
    : IntVal (private_dP privKey)
    : IntVal (private_dQ privKey)
    : IntVal (fromIntegral $ private_qinv privKey)
    : End Sequence
    : xs

  fromASN1 ( Start Sequence
           : IntVal 0
           : IntVal n
           : IntVal e
           : IntVal d
           : IntVal p1
           : IntVal p2
           : IntVal pexp1
           : IntVal pexp2
           : IntVal pcoef
           : End Sequence
           : xs) =
    Right (PKCS1PrivKey privKey, xs)
    where
      calculate_modulus n' i = if (2 ^ (i * 8)) > n' then i else calculate_modulus n' (i+1)
      privKey =
        PrivateKey
        { private_pub  = PublicKey { public_size = calculate_modulus n 1
                                   , public_n    = n
                                   , public_e    = e
                                   }
        , private_d    = d
        , private_p    = p1
        , private_q    = p2
        , private_dP   = pexp1
        , private_dQ   = pexp2
        , private_qinv = pcoef
        }

  fromASN1 ( Start Sequence
           : IntVal 0
           : Start Sequence
           : OID [1, 2, 840, 113549, 1, 1, 1]
           : Null
           : End Sequence
           : OctetString bs
           : xs
           ) =
    let inner = either strError fromASN1 $ decodeASN1' BER bs
        strError = Left . ("fromASN1: RSA.PrivateKey: " ++) . show
    in either Left (\(k, _) -> Right (k, xs)) inner

  fromASN1 _ =
    Left "fromASN1: RSA.PrivateKey: unexpected format"

