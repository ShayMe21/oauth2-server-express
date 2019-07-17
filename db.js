let CLIENTS = [
  {id: '1', secret: 'secret1', redirect_uri: ['https://thameera.com/callback']}
]

let AUTHZ_CODE = []
let ACCESS_TOKENS = []

const getClientById = id => {
  return CLIENTS.find(c => c.id === id);
};

const saveAuthZCodeContext = ctx => {
  AUTHZ_CODE.push(ctx)
}

const getCodeContext = code => {
  return AUTHZN_CODES.find(ctx => ctx.code === code)
}

const deleteCodeContext = code => {
  AUTHZ_CODE.filter(ctx => ctx.code !== code)
}

const saveAccessToken = ctx => {
  ACCESS_TOKENS.push(ctx)
}

module.exports = {
  getClientById,
  saveAuthZCodeContext,
  getCodeContext,
  saveAccessToken
}