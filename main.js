const express = require('express')
const morgan = require('morgan')
const cors = require('cors')
const jwt = require('jsonwebtoken')
const sha256 = require('sha256')
const mysql = require('mysql2')

// Declare the port to run server on
const PORT = parseInt(process.argv[2]) || parseInt(process.env.PORT) || 3008
// Create an instance of express
const app = express()

// disable cache
app.disable('etag');
// Log incoming requests using morgan
app.use(morgan('tiny'))
// Parse application/x-www-form-urlencoded
app.use(express.urlencoded({extended: false}))
// Parse application/json
app.use(express.json())
// Apply cors headers to resp
app.use(cors())

// Sign a jwt token
const signToken = (payload) => {
    const currTime = (new Date()).getTime() / 1000
    const signedToken = jwt.sign({
        ...payload,
        iss: 'tic2301',
        iat: currTime,
    }, 'secret_key')
    return `Bearer ${signedToken}`
}

/* -------------------------------------------------------------------------- */
//               ######## UNPROTECTED REQUESTS ########
/* -------------------------------------------------------------------------- */

/* -------------------------------------------------------------------------- */
//               ######## AUTHENTICATION MIDDLEWARE ########
/* -------------------------------------------------------------------------- */

app.use((req, resp, next) => {
    const auth = req.get('Authorization')
    if (auth == null || auth == '') {
        resp.status(403)
        resp.type('application/json')
        resp.json({message: 'Missing Authorization Header.'})
        return
    }
    const terms = auth.split(' ')
    if ((terms.length != 2) || (terms[0] != 'Bearer')) {
        resp.status(403)
        resp.json({message: 'Incorrect Authorization'})
        return
    }
    const token = terms[1]
    jwt.verify(token, 'secret_key', (err, decoded) => {
        if (err) {
            resp.status(403)
            resp.type('application/json')
            resp.json({message: 'Incorrect Token: ' + err})
        } else {
            req.token = decoded
            next()
        }
    })
})

/* -------------------------------------------------------------------------- */
//                 ######## PROTECTED REQUESTS ########
/* -------------------------------------------------------------------------- */

/* -------------------------------------------------------------------------- */
//                 ######## SERVER STUFF ########
/* -------------------------------------------------------------------------- */

const POOL = mysql.createPool({
    host: 'localhost',
    user: 'root',
    database: 'employees',
    password: 'passw0rd', // Change password to password of ur db
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
});

// Tests the MySQL server
const CHECK_MYSQL_CONN = () => {
    POOL.getConnection((err, conn) => {
        if (err) {
            return Promise.reject(e)
        }
        conn.query('SELECT NOW()');
        console.info('MySQL server is working.')
        POOL.releaseConnection(conn);
        return Promise.resolve();
    })
}

Promise.all([CHECK_MYSQL_CONN()])
.then(() => {
    app.listen(PORT, () => {
        console.info(`Application is listening PORT ${PORT} at ${new Date()}`);
    })
}).catch(e => {
    console.info('Error starting the server: ', e);
})