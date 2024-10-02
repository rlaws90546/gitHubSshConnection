# gitHubSshConnection
Continuation of pacLabsSshTest1, should be cleaner though :)

Steps to convert public RSA key to PEM file (accepted in Java program):
  1. $ssh-keygen -f .ssh/id_rsa.pub -e -m pem
  2. $touch .ssh/id_rsa_pkcs1.pub (and copy contents from above into id_rsa_pkcs1.pub)
  3. $openssl rsa -pubin -in .ssh/id_rsa_pkcs1.pub -RSAPublicKey_in -outform PEM -out .ssh/pubkey_x509.pem

Steps to convert private RSA key to PEM file (accepted in Java program):
  1. $ssh-keygen -p -m PEM -f ~/.ssh/id_rsa
  2. $openssl pkcs8 -topk8 -inform PEM -outform PEM -in .ssh/id_rsa -out .ssh/id_rsa_pkcs8.pem -nocrypt
     (To check that this worked use “$cat .ssh/id_rsa_pkcs8.pem”)
