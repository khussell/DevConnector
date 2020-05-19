const jwt = require('jsonwebtoken');
const config = require('config');

module.exports = function(req, res, next) {
    //Get token from header
    //When we send request to protected route we need to send token within header
    const token = req.header('x-auth-token');

    //Check if no token
    if(!token) {
        return res.status(401).json({msg: 'No token, auth denied'});
    }

    try {
        const decoded = jwt.verify(token, config.get('jwtSECRET'))

        req.user = decoded.user;
        next();
    } catch(err) {
        res.status(401).json({msg: 'Token is not valid.'})
    }
}