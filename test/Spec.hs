{-# Language OverloadedStrings #-}
{-# Language ScopedTypeVariables #-}
import Conduit
import qualified Control.Exception as E
import qualified Crypto.Cipher.AES
import qualified Crypto.Cipher.Blowfish
import qualified Crypto.Cipher.CAST5
import qualified Crypto.Cipher.Camellia
import qualified Crypto.Cipher.Twofish
import qualified Crypto.Cipher.Conduit as Cipher
import           Crypto.Cipher.Types (BlockCipher(blockSize), KeySizeSpecifier(..), IV, makeIV, Cipher(..))
import qualified Crypto.Cipher.Types as ReferenceCipher
import qualified Crypto.Cipher.ChaChaPoly1305.Conduit as ChaCha
import qualified Crypto.ECC as ECC
import Crypto.Error
import Crypto.Hash
import Crypto.MAC.HMAC
import Crypto.MAC.HMAC.Conduit
import qualified Crypto.PubKey.ECIES.Conduit as PubKey
import Crypto.Random
import Data.ByteArray.Encoding
import Data.Proxy (Proxy (..))
import Data.Word (Word8)
import Data.Maybe
import Test.Tasty
import Test.Tasty.HUnit
import Test.Tasty.QuickCheck
import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as BL

main :: IO ()
main = defaultMain tests

tests :: TestTree
tests = testGroup "Cryptonite conduit tests"
    [ testGroup "HMAC"
        [ testCase "File HMAC is correct" testFileHMAC
        ]
    , testGroup "ChaChaPoly1305"
        [ testProperty "encrypt/decrypt works" (ioProperty . propChaChaPoly1305)
        ]
    , testGroup "publicECC"
        [ testProperty "encrypt/decrypt works" (ioProperty . propPublicECC)
        ]
    , testGroup "Cipher"
        [ testCipher (Proxy :: Proxy Crypto.Cipher.AES.AES128)
        , testCipher (Proxy :: Proxy Crypto.Cipher.AES.AES192)
        , testCipher (Proxy :: Proxy Crypto.Cipher.AES.AES256)
        , testCipher (Proxy :: Proxy Crypto.Cipher.Blowfish.Blowfish)
        , testCipher (Proxy :: Proxy Crypto.Cipher.Blowfish.Blowfish64)
        , testCipher (Proxy :: Proxy Crypto.Cipher.Blowfish.Blowfish128)
        , testCipher (Proxy :: Proxy Crypto.Cipher.Blowfish.Blowfish256)
        , testCipher (Proxy :: Proxy Crypto.Cipher.Blowfish.Blowfish448)
        , testCipher (Proxy :: Proxy Crypto.Cipher.CAST5.CAST5)
        , testCipher (Proxy :: Proxy Crypto.Cipher.Camellia.Camellia128)
        -- DES is slow, totaling over a minute on an Intel i9 8950HK (2018)
        -- , testCipher (Proxy :: Proxy Crypto.Cipher.DES.DES)
        -- , testCipher (Proxy :: Proxy Crypto.Cipher.TripleDES.DES_EEE3)
        -- , testCipher (Proxy :: Proxy Crypto.Cipher.TripleDES.DES_EDE3)
        -- , testCipher (Proxy :: Proxy Crypto.Cipher.TripleDES.DES_EEE2)
        -- , testCipher (Proxy :: Proxy Crypto.Cipher.TripleDES.DES_EDE2)
        , testCipher (Proxy :: Proxy Crypto.Cipher.Twofish.Twofish128)
        , testCipher (Proxy :: Proxy Crypto.Cipher.Twofish.Twofish192)
        , testCipher (Proxy :: Proxy Crypto.Cipher.Twofish.Twofish256)
        ]
    ]

testFileHMAC :: Assertion
testFileHMAC = do
    let source = BL.take (1024 * 1024 * 3 + 150) $ BL.iterate (+ 1) 0
    testhmac <- runConduit $ sourceLazy source $$ sinkHMAC ("foobar" :: BS.ByteString)
    let hexdump = convertToBase Base16 (testhmac :: HMAC SHA512t_256)
    assertEqual "HMAC mismatch" "ab78ef7a3a7b02b2ef50ee1a17e43ae0c134e0bece468b047780626264301831" (hexdump :: BS.ByteString)

propChaChaPoly1305 :: [[Word8]] -> IO Bool
propChaChaPoly1305 octets = do
    let chunksIn = map BS.pack octets
    nonce <- getRandomBytes 12
    key <- getRandomBytes 32
    chunksOut <- runConduit
       $ mapM_ yield chunksIn
      .| ChaCha.encrypt nonce key
      .| ChaCha.decrypt key
      .| sinkLazy
    return $ BL.fromChunks chunksIn == chunksOut

propPublicECC :: [[Word8]] -> IO Bool
propPublicECC octets = do
    let chunksIn = map BS.pack octets
    ECC.KeyPair point scalar <- ECC.curveGenerateKeyPair (Proxy :: Proxy ECC.Curve_P256R1)
    chunksOut <- runConduit
       $ mapM_ yield chunksIn
      .| PubKey.encrypt point
      .| PubKey.decrypt scalar
      .| sinkLazy
    return $ BL.fromChunks chunksIn == chunksOut

testCipher :: forall cipher. BlockCipher cipher => Proxy cipher -> TestTree
testCipher cipherP = testGroup (cipherName (undefined :: cipher))
  [ testProperty "ctrCombine . ctrCombine = id" (propCtrCombineInverts cipherP)
  , testProperty "ctrCombine matches reference" (propCtrCombineMatches cipherP)
  ]

propCtrCombineInverts :: forall cipher. BlockCipher cipher => Proxy cipher -> Gen Property
propCtrCombineInverts _ = do
  cipher <- genCipher
  iv <- genIV (cipher :: cipher)
  src <- genSource
  pure $ ioProperty $ do
    expected <- runConduit $ do
      src .| sinkLazy
    actual <- runConduit $ do
      src .| Cipher.ctrCombine cipher iv .| Cipher.ctrCombine cipher iv .| sinkLazy
    pure $ expected === actual

propCtrCombineMatches :: forall cipher. BlockCipher cipher => Proxy cipher -> Gen Property
propCtrCombineMatches _ = do
  cipher <- genCipher
  iv <- genIV (cipher :: cipher)
  src <- genSource
  pure $ ioProperty $ do
    expected <- fmap (ReferenceCipher.ctrCombine cipher iv . BL.toStrict) . runConduit $ do
      src .| sinkLazy
    actual <- fmap BL.toStrict . runConduit $ do
      src .| Cipher.ctrCombine cipher iv .| sinkLazy
    pure $ expected === actual


----- Quickcheck generators -----

genSource :: Monad m => Gen (ConduitT a BS.ByteString m ())
genSource = mapM_ yield . map BS.pack <$> arbitrary

genIV :: BlockCipher cipher => cipher -> Gen (IV cipher)
genIV cipher = do
  bs <- sequence $ [ arbitrary | _ <- [1 .. (blockSize cipher)]]
  pure $ fromMaybe (error "programming error in genIV") $ makeIV $ BS.pack (bs :: [Word8])

genKeySize :: KeySizeSpecifier -> Gen Int
genKeySize (KeySizeEnum ns) = oneof (map pure ns)
genKeySize (KeySizeFixed n) = pure n
genKeySize (KeySizeRange mini maxi) = choose (mini, maxi)

genCipher :: forall cipher. BlockCipher cipher => Gen cipher
genCipher = do
  let keySizeSpec = cipherKeySize (undefined :: cipher)
  keySize <- genKeySize keySizeSpec
  bs <- sequence $ [ arbitrary | _ <- [1 .. keySize]]
  case cipherInit $ BS.pack (bs :: [Word8]) of
    CryptoPassed c -> pure c
    CryptoFailed e -> E.throw (userError ("genCipher: " <> show e))
