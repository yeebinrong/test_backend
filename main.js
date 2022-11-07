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

const signToken = () => {
    const currTime = (new Date()).getTime() / 1000
    const signedToken = jwt.sign({
        iss: 'tic2301',
        iat: currTime,
    }, 'secret_key')
    return `Bearer ${signedToken}`
}

const escapeQuotes = (str) => {
    return `${str}`.replace(/'/g, "''");
}

/* -------------------------------------------------------------------------- */
//               ######## UNPROTECTED REQUESTS ########
/* -------------------------------------------------------------------------- */

app.get('/api/vulnerable_endpoint', async (req, resp) => {
    const emp_no = req.query.emp_no
    try {
        const [rows] = await POOL.promise().query('SELECT * FROM employees WHERE emp_no = ' + emp_no
        );
        resp.status(200)
        resp.type('application/json')
        resp.json({ rows })
    } catch (e) {
        resp.status(400)
        resp.type('application/json')
        resp.json({ error: e })
    }
})

app.get('/api/vulnerable_union_endpoint', async (req, resp) => {
    const emp_no = req.query.emp_no
    try {
        //emp_no = 1 OR 1=1 LIMIT 10) UNION (SELECT * FROM employees LIMIT 10
        const [rows] = await POOL.promise().query('(SELECT * FROM employees WHERE emp_no = ' + emp_no + ')'
        );
        resp.status(200)
        resp.type('application/json')
        resp.json({ rows })
    } catch (e) {
        resp.status(400)
        resp.type('application/json')
        resp.json({ error: e })
    }
})

// Get token for Authorization header from this endpoint
app.get('/api/get_token', async (req, resp) => {
    resp.status(200)
    resp.type('application/json')
    resp.json({ token: signToken() })
})

/* -------------------------------------------------------------------------- */
//               ######## AUTHENTICATION MIDDLEWARE ########
/* -------------------------------------------------------------------------- */

// SKIP THIS PART, GO TO PROTECTED REQUESTS
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

// 1. All endpoints below here will require Authorization header in the request
// You can retrieve the token from the get_token api at line 73, this prevents
// unauthorised users from accessing the endpoint

// 2. All endpoints below here are also configured not to return the error from
// the database, but rather a generic error, so users cannot infer the behaviour
// from the error response.


// Input first_name is escaped and validated before querying the database
app.get('/api/validate_and_escape', async (req, resp) => {
    let first_name = req.query.first_name
    console.log("Unescaped first_name: " + first_name) // Escape Quotes
    first_name = escapeQuotes(first_name)
    console.log("Escaped first_name: " + first_name)
    console.log(`Validating input [${first_name}] to check if it is a string...`) // Validate Input
    if (!(typeof first_name === 'string' || first_name instanceof String)) {
        console.log(`Expected value [${first_name}] to be a string instead of ${typeof first_name}!`)
        resp.status(400)
        resp.type('application/json')
        resp.json({ error: 'An error has occured. Please contact system administrators.' })
        return
    }
    if (first_name.length > 16) {
        console.log(`Value [${first_name}] is longer than accepted 16 char!`)
        resp.status(400)
        resp.type('application/json')
        resp.json({ error: 'An error has occured. Please contact system administrators.' })
        return
    }
    console.log(`Input [${first_name}] validated successfully...`)
    try {
        console.log('Sending request to database...') // Eg. KEY = first_name VALUE = Georgi
        const [rows] = await POOL.promise().query('SELECT * FROM employees WHERE first_name = \'' + first_name + '\' LIMIT 2');
        console.log(`Response from database is: `)
        console.log(rows)
        resp.status(200)
        resp.type('application/json')
        resp.json({ rows })
        return
    } catch (e) {
        console.log(e);
        resp.status(400)
        resp.type('application/json')
        resp.json({ error: 'An error has occured. Please contact system administrators.' })
        return
    }
})

// Function to check if value is numeric
const isNumeric = (value) => {
    return /^-?\d+$/.test(value);
}

// On top of escaping and validating input, the query is parameterised
app.get('/api/parameterised_query', async (req, resp) => {
    let emp_no = req.query.emp_no
    if (isNumeric(emp_no)) {
        emp_no = parseInt(emp_no);
    }
    console.log(`Validating input [${emp_no}] to check if it is a number...`) // Validate Input
    if (!(typeof emp_no === 'number' || emp_no instanceof Number)) {
        console.log(`Expected value [${emp_no}] to be a number instead of ${typeof emp_no}!`)
        resp.status(400)
        resp.type('application/json')
        resp.json({ error: 'An error has occured. Please contact system administrators.' })
        return
    }
    console.log(`Input [${emp_no}] validated successfully...`)
    try {
        console.log('Sending request to database...') // Eg. KEY = emp_no VALUE = 10001
        // Parameterise the query
        const [rows] = await POOL.promise().query('SELECT * FROM employees WHERE emp_no = ?',
            [ emp_no ],
        );
        console.log(`Response from database is: `)
        console.log(rows)
        resp.status(200)
        resp.type('application/json')
        resp.json({ rows })
    } catch (e) {
        resp.status(400)
        resp.type('application/json')
        resp.json({ error: 'An error has occured. Please contact system administrators.' })
    }
})

/* -------------------------------------------------------------------------- */
//                 ######## SERVER STUFF ########
/* -------------------------------------------------------------------------- */

const POOL = mysql.createPool({
    host: 'localhost',
    user: 'root',
    database: 'employees',
    password: 'passw0rd', // Change password to password of ur db
    waitForConnections: true,
    multipleStatements: true,
    connectionLimit: 10,
    queueLimit: 0
});

// Tests the MySQL server
const CHECK_MYSQL_CONN = () => {
    POOL.getConnection((err, conn) => {
        if (err) {
            return Promise.reject(err)
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