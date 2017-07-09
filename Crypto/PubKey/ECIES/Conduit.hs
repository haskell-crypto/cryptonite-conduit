module Crypto.PubKey.ECIES.Conduit
  ( encrypt
  , decrypt
  ) where

import           Control.Monad.Catch                  (MonadThrow, throwM)
import           Control.Monad.Trans.Class            (lift)
import qualified Crypto.Cipher.ChaCha                 as ChaCha
import qualified Crypto.Cipher.ChaChaPoly1305.Conduit as ChaCha
import qualified Crypto.ECC                           as ECC
import qualified Crypto.Error                         as CE
import           Crypto.Hash                          (SHA512 (..), hashWith)
import           Crypto.PubKey.ECIES                  (deriveDecrypt,
                                                       deriveEncrypt)
import           Crypto.Random                        (MonadRandom)
import qualified Data.ByteArray                       as BA
import           Data.ByteString                      (ByteString)
import qualified Data.ByteString                      as B
import qualified Data.ByteString.Lazy                 as BL
import           Data.Conduit                         (ConduitM, yield)
import qualified Data.Conduit.Binary                  as CB
import           Data.Proxy                           (Proxy (..))

getNonceKey :: ECC.SharedSecret -> (ByteString, ByteString)
getNonceKey shared =
  let state1 = ChaCha.initializeSimple $ B.take 40 $ BA.convert $ hashWith SHA512 shared
      (nonce, state2) = ChaCha.generateSimple state1 12
      (key, _) = ChaCha.generateSimple state2 32
   in (nonce, key)

type Curve = ECC.Curve_P256R1

proxy :: Proxy Curve
proxy = Proxy

encrypt
  :: (MonadThrow m, MonadRandom m)
  => ECC.Point Curve
  -> ConduitM ByteString ByteString m ()
encrypt point = do
  (point', shared) <- lift $ deriveEncrypt proxy point
  let (nonce, key) = getNonceKey shared
  yield $ ECC.encodePoint proxy point'
  ChaCha.encrypt nonce key

decrypt
  :: (MonadThrow m)
  => ECC.Scalar Curve
  -> ConduitM ByteString ByteString m ()
decrypt scalar = do
  pointBS <- fmap BL.toStrict $ CB.take 65 -- magic value, known size of point
  point <-
    case ECC.decodePoint proxy pointBS of
      CE.CryptoPassed point -> return point
      CE.CryptoFailed e -> throwM e
  let shared = deriveDecrypt proxy point scalar
      (_nonce, key) = getNonceKey shared
  ChaCha.decrypt key
