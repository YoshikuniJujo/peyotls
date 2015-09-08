import Network
import Network.PeyoTLS.Codec.Hello

main :: IO ()
main = do
	h <- connectTo "localhost" $ PortNumber 443
	return ()
