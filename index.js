const express = require('express')
const cors = require('cors')
const {connect} = require('mongoose')
require('dotenv').config()
const upload = require('express-fileupload')

const userRoutes = require('./routes/userRoutes')
const postRoutes = require('./routes/postRoutes')
const {notFound, errorHandler} = require('./middleware/errorMiddleware')

const app = express();
app.use(express.json({extended: true}))
app.use(express.urlencoded({extended: true}))
const corsOptions = {
  origin: 'https://renn-blog.vercel.app', // Ganti dengan origin frontend Anda!
  methods: 'GET,HEAD,PUT,PATCH,POST,DELETE', // Metode HTTP yang diizinkan
  credentials: true, // Izinkan cookie dan header otorisasi
  optionsSuccessStatus: 204, // Beberapa browser membutuhkan ini untuk status 204
  allowedHeaders: 'Content-Type,Authorization', // Header yang diizinkan
};

app.use(cors(corsOptions));
app.use(upload())
app.use('/uploads', express.static(__dirname + '/uploads'))

app.use('/api/users', userRoutes)
app.use('/api/posts', postRoutes)

app.use(notFound)
app.use(errorHandler)

connect(process.env.MONGO_URI).then(app.listen(process.env.PORT || 5000, ()=> console.log(`Server started on port ${process.env.PORT}`))).catch(error => {console.log(error)})
