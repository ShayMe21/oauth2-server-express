const express = require('express')
const db = require('./db')
const moment = require('moment')
const randomstring = require('randomstring')

const app = express()

app.use(express.urlencoded({extended: true}))
app.use(express.json())

app.set('view engine', 'ejs')

app.get('/', (req, res) => {
  res.send("Welcome to my OAuth2 server!!")
})

app.get('/authorize', (req, res) => {
  const clientID = req.query.client_id;
  // Client ID validation
  if (!clientID){
    res.status(400).render('error',
    {message: `Required parameter is missing: client_id`})
  }

  const client = db.getClientById(clientID)

  if (!client){
    res.status(400).render('error',
    {message: `Invalid client_id`})
  }

  // Response Type validations
  const responseType = req.query.response_type;

  if (!responseType){
    res.status(400).render('error',
    {message: `Required parameter is missing: response_type`})
  }

  const supportedResponseTypes = [
    'code'
  ]

  if (!supportedResponseTypes.includes(responseType)){
    res.status(400).render('error',
    {message: `Invalid response_type`})
  }

  // Redirect URIs Validations
  const validURIs = client.redirect_uri;
  let redirectUri = req.query.redirect_uri || null;

  if (!validURIs || !validURIs.length){
    res.status(400).render('error',
    {message: `No redirect_uri configured for the client`})
  }

  if (redirectUri && !validURIs.includes(redirectUri)){
    res.status(400).render('error',
    {message: `Invalid redirect_uri specified: ${redirectUri}`})
  }

  if (!redirectUri){
    redirectUri = client.redirect_uri[0];
  }

  // Check Session
  // If no session redirect to login page
  // We assume there's a session here

  // create authz code
  const AuthZCode = randomstring.generate({length:32})

  console.log(AuthZCode)

  const expiresAt = moment().add(10, 'minutes').valueOf()
  console.log(expiresAt)

  let context = {
    AuthZCode,
    expiresAt,
    clientID,
    redirectUri: req.query.redirect_uri,
    user_id: '1'
  }

  // Save AuthzCode to DB
  db.saveAuthZCodeContext(context)

  var URL = require('url').URL;
  var myURL = new URL(redirectUri);
  myURL.searchParams.set('code', AuthZCode)

  res.redirect(myURL);
})

// Authorization Code Exchange
app.post('/token', (req,res) => {
  const body = req.body || null;

  if (!body){
    return res.status(400).json({error: 'invalid_request', error_description: 'request body missing'})
  }

  const grant = body.grant_type;

  if(!grant){
    return res.status(400).json({error: 'invalid_request', error_description: 'grant_type not specified.'})
  }

  if (grant !== 'authorization_code'){
    return res.status(400).json({error: 'unsupported_grant_type', error_description: 'grant_type not supported.'})
  }

  const authHeader = req.headers['authorization']
  let client = null;

  if (authHeader){
    console.log(authHeader)
    // Basic Authorization
    const parts = authHeader.trim().split(' ');
    console.log(parts)

    if (parts.length !== 2 || parts[0].toLowerCase() !== 'basic'){
      res.set('WWW-Authenticate', 'Basic')
      return res.status(400).json({error: 'invalid_request', message: 'Unsupported authentication format.'})
    }

    const creds = Buffer.from(parts[1], 'base64').toString('ascii').split(':')
    const client = db.getClientById(creds[0])
    console.log(creds)
    console.log(client)

    if (!client || client.secret !== creds[1]){
      res.set('WWW-Authenticate', 'Basic')
      return res.status(400).json({error: 'invalid_request', message: 'Invalid client Id or secret'})
    }

    if (!body.code){
      return res.status(400).json({error: 'invalid_request', message: 'Missing required parameter: code'})
    }
    
    console.log("returning from basic auth if statement")



  } else {
    // Json body auth method
    if (!body.client_id || !body.client_secret){
      return res.status(401).json({error: 'invalid_client', error_description: 'Client authentication failed'})
    }

    const client = db.getClientById(body.client_id)

    if (!client || client.secret !== body.client_secret){
      return res.status(401).json({error: 'invalid_request', message: 'Invalid client Id or secret'})
    }

    if (!body.code){
      return res.status(400).json({error: 'invalid_request', message: 'Missing required parameter: code'})
    }

    const ctx = db.getCodeContext(body.code)
    if (!ctx){
      return res.status(400).json({ error:'invalid_grant', error_description: 'Invalid authorization code' })
    }

    db.deleteCodeContext(body.code)

    if (moment().after(ctx.expiresAt)){
      return res.status(400).json({ error:'invalid_grant', error_description: 'Invalid authorization code' })
    }

    if (ctx.clientID !== client.id){
      return res.status(400).json({ error:'invalid_grant', error_description: 'Invalid authorization code' })
    }

    if (ctx.redirectUri){
      if (body.redirect_uri !== ctx.redirectUri){
        return res.status(400).json({error: 'invalid_grant', error_description: 'Invalid redirect_uri'})
      }
    }

    const token = 'at-' + randomstring.generate({length: 32, charset: 'alphanumeric'})

    let tokenCtx = {
      token,
      expiresAt: moment().add(120, 'minutes').valueOf(),
      clientID: ctx.clientID,
      userID: ctx.userID
    }

    db.saveAccessToken(tokenCtx)

    res.set('Cache-Control', 'no-store')
    res.set('Pragma', 'no-store')
    res.status(200).json({
      accessToken: token,
      expires_in: 120 * 60,
      token_type: 'Bearer'
    })


  }

});

const PORT = 8500

app.listen(PORT, () => console.log(`Listening on port: ${PORT}`))