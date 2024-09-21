const {Schema, model, isValidObjectId, default: mongoose} = require('mongoose')

const userSchema = new Schema({
    _id: {type: mongoose.SchemaTypes.ObjectId},
    name: {type: String, required: true},
    email: {type: String, required: true},
    password: {type: String, required: true},
    avatar: {type: String},
    post: {type: Number, default: 0}
})

module.exports = model('User', userSchema)