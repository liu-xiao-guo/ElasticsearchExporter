from elasticsearch import Elasticsearch

def LoadSettings():

  #command to get the SHA-256 fingerprint from the elasticsearch server
  #openssl s_client --connect 192.168.1.1:9200 </dev/null | sed -ne '/-BEGIN CERTIFICATE-/,/-END CERTIFICATE-/p' | openssl x509 -noout -in - --fingerprint -sha256

  CERT_FINGERPRINT="bd0a26dc646ef1cb3cb5e132e77d6113e1b46d56ee390dd3c6f0b2d2b16962c4"

  es = Elasticsearch(  ['https://localhost:9200'],
    basic_auth = ('elastic', 'h6y=vgnen2vkbm6D+z6-'),
    ssl_assert_fingerprint = CERT_FINGERPRINT,
    http_compress = True )

  settings = { 'es' : es }

  settings['TimeSeries'] = True
  settings['timestamp'] = 'timestamp'
  
  #The filename used when no group is defined 
  settings['FileNameOther'] = 'Other'

  #enable debug logging
  settings['debug'] = False

  return settings

if __name__ == '__main__':
  print ("This is the config and settings for Elasticsearch Exporter")
