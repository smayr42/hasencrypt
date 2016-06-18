module Utils
  ( throwIfNot
  , throwIfNothing
  , throwIfError

  , bsToInteger
  , integerToBS

  , unfoldUntilM
  , OptDescrEx(..)
  , getOptReq

  , module Exports
  , module GetOpt
  ) where

import           Control.Arrow         ((***))
import           Control.Monad         as Exports
import           Control.Monad.Catch
import qualified Data.ByteString       as B
import           Data.Maybe            as Exports
import           Data.Monoid           as Exports
import           Data.String           as Exports
import           Data.Text.Encoding    as Exports (decodeUtf8, encodeUtf8)
import           Data.Tuple            (swap)
import           Data.Typeable         as Exports
import           Safe                  as Exports
import           System.Console.GetOpt as GetOpt

throwIfNot :: (MonadThrow m, Exception e) => e -> Bool -> m ()
throwIfNot e b = if not b then throwM e else pure ()

throwIfNothing :: (MonadThrow m, Exception e) => e -> Maybe a -> m a
throwIfNothing e = maybe (throwM e) pure

throwIfError :: (MonadThrow m, Exception e) => (a -> e) -> Either a b -> m b
throwIfError f = either (throwM . f) pure

bsToInteger :: B.ByteString -> Integer
bsToInteger = B.foldl (\acc x -> acc * 256 + toInteger x) 0

integerToBS :: Integer -> B.ByteString
integerToBS = B.reverse . B.unfoldr (fmap swap <$> gen)
  where
    gen x = if x == 0 then Nothing else Just (fromIntegral <$> quotRem x 256)

unfoldUntilM :: (Monad m) => (a -> Bool) -> (a -> m a) -> a -> m [a]
unfoldUntilM p f v
  | p v       = return [v]
  | otherwise = f v >>= \v' -> (v:) <$> unfoldUntilM p f v'

data OptDescrEx a = ReqOption { getOptDescr :: OptDescr a }
                  | OptOption { getOptDescr :: OptDescr a }

getOptReq :: [OptDescrEx a] -> [String] -> (Bool, [a], [String], [String])
getOptReq descrs args =
  case getOpt Permute options' args of
    (opts, rest, errs) ->
        let (present, opts') = foldl (flip id) ([], []) opts
        in (required `subsetOf` present, opts', rest, errs)
  where
    options' = extOptFun . getOptDescr <$> descrs
    extOptFun (Option s l arg d) = Option s l (extArgFun l arg) d
    extArgFun l (ReqArg f s) = ReqArg (\o -> (:) l *** (:) (f o)) s
    extArgFun l (OptArg f s) = OptArg (\o -> (:) l *** (:) (f o)) s
    extArgFun l (NoArg f) = NoArg $ (:) l *** (:) f
    required = [l | ReqOption (Option _ l _ _) <- descrs]
    subsetOf xs ys = all (`elem` ys) xs

