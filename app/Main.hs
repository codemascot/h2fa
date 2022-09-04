module Main where

import Data.Word (Word8, Word64)
import Data.Time (getCurrentTime)
import Text.Read (readEither) -- `readMaybe` could've been used as well.
import HMAC.H2fa (totpSha1, decodeKey)

main :: IO ()
main = do
        putStrLn "Input the key: "
        key  <- getLine
        putStrLn "Delay (in Seconds): "
        delay <- getLine
        putStrLn "Number of base10 digits in TOTP value: "
        number <- getLine
        time <- getCurrentTime
        -- TODO: Need refactor with maybe monad
        case decodeKey key of
          Left  error -> putStrLn "Error!"
          Right value -> case readEither delay :: Either String Word64 of
                           Left error' -> putStrLn "For delay value, only integer is allowed!"
                           Right delay' -> case  readEither number :: Either String Word8 of
                                             Left error'' -> putStrLn "For base10, only integer is allowed!"
                                             Right number' -> print $ totpSha1 value time delay' number'
