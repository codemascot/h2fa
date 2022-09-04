module HMAC.H2fa where

import Data.Bits
import Data.Word
import Data.Time
import Data.Time.Clock.POSIX
import Data.ByteString.Base32

import Data.Text ( Text, pack )
import Data.Text.Encoding ( encodeUtf8 )

import qualified Data.ByteString       as BS
import qualified Data.ByteString.Char8 as BS.C8
import qualified Data.ByteString.Lazy  as BS.L
import qualified Data.Digest.Pure.SHA  as SHA
import Data.ByteString (ByteString)
import Text.Read (readMaybe, readEither)

-- | Shared secret encoded as raw octets
type Secret = BS.ByteString

-- | Hash algorithm used for HOTP\/TOTP computations
data HashAlgorithm = SHA1
                   | SHA256
                   | SHA512
                   deriving (Eq,Show)

hmac :: HashAlgorithm -> Secret -> Secret -> Secret
hmac alg key msg = case alg of
    SHA1   -> BS.L.toStrict (SHA.bytestringDigest (SHA.hmacSha1   (BS.L.fromStrict key) (BS.L.fromStrict msg)))
    SHA256 -> BS.L.toStrict (SHA.bytestringDigest (SHA.hmacSha256 (BS.L.fromStrict key) (BS.L.fromStrict msg)))
    SHA512 -> BS.L.toStrict (SHA.bytestringDigest (SHA.hmacSha512 (BS.L.fromStrict key) (BS.L.fromStrict msg)))

-- DT(HS)
trunc :: Secret -> Word32
trunc b = case bsToW32 rb of
            Left e    -> error e
            Right res -> res .&. (0x80000000 - 1) -- reset highest bit
  where
    offset = BS.last b .&. 15 -- take low 4 bits of last byte
    rb = BS.take 4 $ BS.drop (fromIntegral offset) b -- resulting 4 byte value

-- StToNum(Sbits)
bsToW32 :: Secret -> Either String Word32
bsToW32 bs = case BS.unpack bs of
               [ b0, b1, b2, b3 ] -> Right $! (((((fI b0 `shiftL` 8) .|. fI b1) `shiftL` 8) .|. fI b2) `shiftL` 8) .|. fI b3
               _                  -> Left "bsToW32: the impossible happened"
  where
    fI = fromIntegral

bsFromW64 :: Word64 -> Secret
bsFromW64 w = BS.pack [ b j | j <- [ 7, 6 .. 0 ] ]
  where
    b j = fromIntegral (w `shiftR` (j*8))

hotp :: HashAlgorithm           -- ^ Hashing algorithm
     -> Secret                  -- ^ Shared secret
     -> Word64                  -- ^ Counter value
     -> Word8                   -- ^ Number of base10 digits in HOTP value
     -> Word32                  -- ^ HOTP value
hotp alg key cnt digits
  | digits >= 10 = snum
  | otherwise    = snum `rem` (10 ^ digits)
  where
    -- Snum  = StToNum(Sbits)
    -- Sbits = DT(HS)
    -- HS    = HMAC(K,C)
    snum = trunc $ hmac alg key $ bsFromW64 cnt

totpCounter :: UTCTime     -- ^ Time of totp
            -> Word64      -- ^ Time range in seconds
            -> Word64      -- ^ Resulting counter
totpCounter time period =
    let timePOSIX = floor $ utcTimeToPOSIXSeconds time in div timePOSIX period

totp :: HashAlgorithm -- ^ Hash algorithm to use
     -> Secret        -- ^ Shared secret
     -> UTCTime       -- ^ Time of TOTP
     -> Word64        -- ^ Time range in seconds
     -> Word8         -- ^ Number of base10 digits in TOTP value
     -> Word32        -- ^ TOTP value
totp alg secr time period = hotp alg secr $ totpCounter time period

totpSha1 :: Secret        -- ^ Shared secret
         -> UTCTime       -- ^ Time of TOTP
         -> Word64        -- ^ Time range in seconds
         -> Word8         -- ^ Number of base10 digits in TOTP value
         -> Word32        -- ^ TOTP value
totpSha1 secr time period = totp SHA1 secr time period

decodeKey :: String -> Either Text ByteString
decodeKey k = decodeBase32 $ BS.C8.pack k
