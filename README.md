# Authentication backend with AWS Cognito

Backend de autenticacion implementado en Python utilizando AWS Cognito. El codigo es una adaptacion del provisto por:  [Part 1, Serverless](https://medium.com/@houzier.saurav/aws-cognito-with-python-6a2867dd02c6)

## Configuracion

Para poder utilizarlo es necesario crear una user pool en cognito. Importante habilitar `ALLOW_ADMIN_USER_PASSWORD_AUTH` como opcion de login.

Documentacion complementaria del [SDK de Cognito](https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/cognito-idp.html)

Para poder utilizarlo es necesario definir un envfile:

.env.auth
```env
USER_POOL_ID=
CLIENT_ID=
CLIENT_SECRET=

ACCESS_ID=
ACCESS_KEY=
ACCESS_TOKEN=
```

Los primeros 3 parametros corresponden a cognito y los ultimos 3 a credenciales de acceso a la sdk de aws. En el lab se consiguen como `AWS Details > AWS CLI`

## Ejecucion

```bash
docker compose up 
```

## Pruebas

Se provee un archivo `sample.http` con pedidos que pueden ser utilziados para probar la aplicacion. Recomendacion en caso de trabajar con VSCode [Rest Client](https://marketplace.visualstudio.com/items?itemName=humao.rest-client)