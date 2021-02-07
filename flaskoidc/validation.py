import python_jwt as jwt
import jwcrypto.jwk as jwk
import datetime

allowed_algs = [
  'RS256',
  'RS384',
  'RS512',
  'PS256',
  'PS384',
  'PS512',
  'ES256',
  'ES384',
  'ES512',
  'HS256',
  'HS384',
  'HS512']

def validate_token(jwkset, token, clock_skew_seconds):

    headers, _ = jwt.process_jwt(token)
    alg = headers['alg']
    kid = headers['kid']

    if not alg:
        raise Exception('No \'alg\' claim in JWT token header')
    
    if not alg in allowed_algs:
        raise Exception('\'%s\' is not an allowed algorithm.' % alg)

    if not kid:
        raise Exception('No \'kid\' claim in JWT token header')

    json_key = jwkset.get_key(kid)

    algorithms = [alg]

    # Exception raised on invalid token input will be bubble up to the caller.
    _, payload = jwt.verify_jwt(token, json_key, algorithms, datetime.timedelta(seconds=clock_skew_seconds), True)

    # typ = payload.get('typ', None)
    # if typ != 'Bearer':
    #    raise Exception('The token is not intended for autorization (\'typ\' should be \'Bearer\', not \'%s\')' % typ)

    return payload
