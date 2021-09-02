// Require `checkUsernameFree`, `checkUsernameExists` and `checkPasswordLength`
// middleware functions from `auth-middleware.js`. You will need them here!
const express = require('express')
const router = express.Router()
const User = require('../users/users-model.js')
const bcrypt = require('bcryptjs')
const { checkUsernameFree, checkUsernameExists, checkPasswordLength } = require('./auth-middleware.js')


/**
  1 [POST] /api/auth/register { "username": "sue", "password": "1234" }

  response:
  status 200
  {
    "user_id": 2,
    "username": "sue"
  }

  response on username taken:
  status 422
  {
    "message": "Username taken"
  }

  response on password three chars or less:
  status 422
  {
    "message": "Password must be longer than 3 chars"
  }
 */

router.post('/register',checkUsernameFree ,checkPasswordLength ,async (req,res)=>{
  try{
    const hash = bcrypt.hashSync(req.body.password,10)
    const newUser = await User.add({username:req.body.username, password:hash})
    res.status(200).json(newUser)
  }catch(e){
        res.status(500).json(`Server error: ${e}`)
    }
})




/**
  2 [POST] /api/auth/login { "username": "sue", "password": "1234" }

  response:
  status 200
  {
    "message": "Welcome sue!"
  }

  response on invalid credentials:
  status 401
  {
    "message": "Invalid credentials"
  }
 */

router.post('/login', checkUsernameExists, async (req,res)=>{
  // this is used to define the data that you want tp compare:
  //const originalUser = await User.findBy({username:req.body.username})
  // const { username, password } = originalUser[0]
  try{
    const verifiedUser = bcrypt.compareSync(req.body.password,req.userData.password)
    if(verifiedUser){
      req.session.user = req.userData.username
      res.json({message: `Welcome back ${req.userData.username}`})
      console.log(`User ${req.userData.username} was logged in successfully!`)
    }else {
      res.status(401).json({err: 'Invalid credentials'})
    }
  }catch(e){
        res.status(500).json({message:e.message})
    }
})


/**
  3 [GET] /api/auth/logout

  response for logged-in users:
  status 200
  {
    "message": "logged out"
  }

  response for not-logged-in users:
  status 200
  {
    "message": "no session"
  }
 */

router.get('/logout', (req,res)=>{
  if(req.session){
    req.session.destroy(err =>{
      if(err){
        res.json('Unable to end session')
      }else{
        res.json('Session ended successfully')
      }
    })
  }else{
    res.json('No session found')
}
})

 
// Don't forget to add the router to the `exports` object so it can be required in other modules
module.exports = router;
