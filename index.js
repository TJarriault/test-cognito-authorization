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
const path = require('path');
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const methodOverride = require('method-override');
const routes = require('./routes');

const app = express();
app.use(cookieParser());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({extended: true})); // for parsing application/x-www-form-urlencoded
app.use(methodOverride());
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(routes);

app.listen(8000, function () {
    console.log("Example app listening at http://localhost:8000");
});
