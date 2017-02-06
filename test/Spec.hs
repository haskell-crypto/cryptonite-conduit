{-# Language OverloadedStrings #-}
import Conduit
import Crypto.Hash
import Crypto.MAC.HMAC
import Crypto.MAC.HMAC.Conduit
import Data.ByteArray.Encoding
import Test.Tasty
import Test.Tasty.HUnit
import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as BL

main :: IO ()
main = defaultMain tests

tests :: TestTree
tests = testGroup "Cryptonite conduit tests"
    [ testGroup "HMAC"
        [ testCase "File HMAC is correct" testFileHMAC
        ]
    ]

testFileHMAC :: Assertion
testFileHMAC = do
    let source = BL.take (1024 * 1024 * 3 + 150) $ BL.iterate (+ 1) 0
    testhmac <- runConduit $ sourceLazy source $$ sinkHMAC ("foobar" :: BS.ByteString)
    let hexdump = convertToBase Base16 (testhmac :: HMAC SHA512t_256)
    assertEqual "HMAC mismatch" "ab78ef7a3a7b02b2ef50ee1a17e43ae0c134e0bece468b047780626264301831" (hexdump :: BS.ByteString)
