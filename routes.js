/**
 * This program belongs to Physalix.
 * It is considered a trade secret, and is not to be divulged or used
 * by parties who have not received written authorization from the owner.
 * For more details please contact us on fs@physalix.com
 *
 * @author   Fabrice Sommavilla <fs@physalix.com>
 * @company  Physalix
 * @version  0.1
 * @date     12/10/2018
 */

const express = require('express');
const router = express.Router();
const request = require('request');
const jwt = require('jsonwebtoken');
const config = require('config');
const AmazonCognitoIdentity = require('amazon-cognito-identity-js');
const AWS = require('aws-sdk');
global.fetch = require('node-fetch');

/**
 *
 */
router.get('/dash', function response(req, res) {
    console.log('res', res.getHeaders());
    const headers = res.getHeaders();
    if (!headers || !headers['x-amzn-oidc-data']) {
        return res.status(500).send({error: "Bad request error", headers: headers});
    }
    let encodeJwt = headers['x-amzn-oidc-data'];
    const jwtHeaders = encodeJwt.split('.')[0];
    const decodedJwtHeaders = Buffer.from(jwtHeaders, 'base64');
    console.log('decodedJwtHeaders', decodedJwtHeaders);
    const decodedJson = JSON.parse(decodedJwtHeaders);
    const kid = decodedJson['kid'];
    const url = `https://public-keys.auth.elb.eu-west-1.amazonaws.com/${kid}`;

    request(url, (error, response, body) => {
        if (error) {
            console.log('error:', error);
            return res.status(500).send(error);
        }
        if (response.statusCode !== 200) {
            console.log('Status code != 200:', response.statusCode);
            return res.status(response.statusCode).send(body);
        }
        console.log('body:', body.text);
        jwt.verify(encodeJwt, body.text, {algorithms: ['ES256']}, (err, decoded) => {
            res.json(decoded);
        });
    });

    res.json({});
});

/**
 *
 */
router.get('/', function response(req, res) {
    res.render('index');
});

/**
 *
 */
router.get('/signin', function response(req, res) {
    res.render('signin');
});

/**
 *
 */
router.post('/login', function response(req, res) {
    console.log(req.body);
    const authenticationData = {
        Username: req.body.username,
        Password: req.body.password
    };
    const authenticationDetails = new AmazonCognitoIdentity.AuthenticationDetails(authenticationData);
    const poolData = {
        UserPoolId: config.aws.userPoolId,
        ClientId: config.aws.appClientId
    };
    const userPool = new AmazonCognitoIdentity.CognitoUserPool(poolData);
    const userData = {
        Username: req.body.username,
        Pool: userPool
    };
    const cognitoUser = new AmazonCognitoIdentity.CognitoUser(userData);
    cognitoUser.authenticateUser(authenticationDetails, {
        onSuccess: function (result) {
            console.log('access token + ' + result.getAccessToken().getJwtToken());
            console.log('id token + ' + result.getIdToken().getJwtToken());
            console.log('refresh token + ' + result.getRefreshToken().getToken());

            AWS.config.region = config.aws.region;
            AWS.config.credentials = new AWS.CognitoIdentityCredentials({
                IdentityPoolId: config.aws.identityPoolId,
                Logins: {
                    [`cognito-idp.${config.aws.region}.amazonaws.com/${config.aws.userPoolId}`]: result.getIdToken().getJwtToken()
                }
            });
            console.log(AWS.config.credentials);
            const data = jwt.decode(result.getIdToken().getJwtToken(), {complete: true});

            if (!data) {
                return res.status(500).send("Not a valid JWT token");
            }

            res.render('authenticated', {
                data: {
                    username: data.payload['cognito:username'],
                    telephone: data.payload.phone_number,
                    email: data.payload.email
                }
            });
        },
        onFailure: err => {
            console.log(err.message || JSON.stringify(err));
            res.render('403');
        }
    });
});


module.exports = router;
