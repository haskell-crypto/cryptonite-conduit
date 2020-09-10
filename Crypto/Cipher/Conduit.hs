{-# LANGUAGE FlexibleContexts #-}
module Crypto.Cipher.Conduit where

import Control.Monad.IO.Class
import Crypto.Cipher.Types
import Data.ByteArray as B
import Data.ByteString (ByteString)
import Data.Conduit
import Data.Conduit.Combinators
import Data.Sequences

ctrCombine :: (BlockCipher cipher, ByteArray ba, IsSequence ba, MonadIO m) => cipher -> IV cipher -> ConduitT ba ba m ()
ctrCombine cipher ivini =
  chunksOfE (fromIntegral $ blockSize cipher)
    .| doCnt ivini
 where
  doCnt iv = do
    chunkMaybe <- await
    case chunkMaybe of
      Nothing -> pure ()
      Just i -> do
        -- This copy is only necessary because can't
        -- make the existential type in IV align with ba
        iv' <- liftIO $ B.copy iv mempty
        let ivEnc = ecbEncrypt cipher (iv' :: ByteString)
        yield (B.xor i ivEnc)
        doCnt (ivAdd iv 1)
