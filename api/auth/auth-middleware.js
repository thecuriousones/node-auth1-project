const User = require('../users/users-model.js');

/*
  If the user does not have a session saved in the server

  status 401
  {
    "message": "You shall not pass!"
  }
*/
function restricted(req,res,next) {
  if(req.session && req.session.user){
    next()
  }else {
    res.status(401).json({message: "You shall not pass!"})
  }
}

/*
  If the username in req.body already exists in the database

  status 422
  {
    "message": "Username taken"
  }
*/
async function checkUsernameFree(req,res,next) {
  try{
    const newUser = await User.findBy({username:req.body.username})
    if(!newUser.length){
      next()
    }else{
      res.status(422).json({message: "Username taken"})
    }
  }catch(e){
        res.status(500).json(`Server error: ${e}`)
    }
}

/*
  If the username in req.body does NOT exist in the database

  status 401
  {
    "message": "Invalid credentials"
  }
*/
async function checkUsernameExists(req,res,next) {
  try{
    const returningUser = await User.findBy({username:req.body.username})
    //returningUser is an array that looks like this [{username:'taetae', password: '389ehdnuidney234hu43984}]
    if(returningUser.length){
      req.userData = returningUser[0]
      next()
    }else {
      res.status(401).json({message: "Invalid credentials"})
    }
  }catch(e){
        res.status(500).json(`Server error: ${e}`)
    }
    console.log(req.userData)
}

/*
  If password is missing from req.body, or if it's 3 chars or shorter

  status 422
  {
    "message": "Password must be longer than 3 chars"
  }
*/
function checkPasswordLength(req,res,next) {
  const password = req.body.password
  if(password.length > 3){
    next()
  }else {
    res.status(422).json({message: "Password must be longer than 3 chars"})
  }

}

// Don't forget to add these to the `exports` object so they can be required in other modules

module.exports = { restricted, checkUsernameFree, checkUsernameExists, checkPasswordLength }
