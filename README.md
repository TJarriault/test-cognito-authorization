# test-cognito-authorization

http://localhost:8000

GET /dash : Path for oauth2 callback (ELB)  
GET /     : Path for Cognito authentication


- Create docker image
- Build container
docker build . -t xxx/test-auth-lb:latest
- Execute container
docker run -d -p 8000:8000 "IMAGE ID"
