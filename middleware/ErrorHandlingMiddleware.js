const ApiError = require('../error/ApiError');

module.exports = function(err, req, res, next) {
    if (err instanceof ApiError) {
        return res.status(err.status).json({message: err.message, error: true, status: err.status});
    }
    return res.status(500).json({message: 'Unhandled error', error: true, status: 500})
}