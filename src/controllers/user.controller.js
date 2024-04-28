const bcrypt = require('bcrypt');
const {users} = require('../models');
const { where } = require('sequelize');
const jwt = require('jsonwebtoken');



// Register service!
const register = async(req, res) => {
    const {firstName, lastName, userName, email, password} = req.body
    
    if(!firstName || !userName || !password) {
        return res.status(400).send({
            message: "Create user failed, field must not be empty!"
        })
    }
    // encrypted password account
    const hashPassword = bcrypt.hashSync(password, 8);

    const newUser = await users.create({
        firstName: firstName,
        lastName: lastName,
        userName:userName,
        email: email,
        password: hashPassword
    })
    return res.status(200).send({
        message: "Create user success!"
    })
}

// Login Service!
const loginUser = async (req, res) => {
    const {userName, password} = req.body

    const getUser = await users.findOne({where: {userName: userName}}); // find data in database to compare, for login service!
    
    if(!getUser) {
        return res.status(400).send({
        message: "Login failed, user not found!"
        })
    };
    
    const comparedPassword = bcrypt.compareSync(password, getUser.dataValues.password); // comparing password within data that stored in database!
    // console.log(comparedPassword); 

        if(!comparedPassword) {
            return res.status(400).send({
            message: "Login failed, incorrect password!"
            })
        };

    const data = getUser.dataValues

    // give access after authentication success!
    const token = jwt.sign({id: data.id, userName: data.userName}, process.env.JWT_SECRET, {expiresIn: 60});
    
    return res.status(200).send({
        message: "Login success!",
        data: token
    })       
        
}



// Update Account Service!
const updateProfile = async (req, res) => {
    const token = req.headers['authorization']
    const dataProfile = jwt.verify(token.split(" ")[1], process.env.JWT_SECRET);
    
    const {firstName, lastName, userName, email, password, picture} = req.body

    const userProfile = await users.update({
        firstName: firstName,
        lastName: lastName,
        userName: userName,
        email: email,
        picture: picture    
        }, {where: {id: dataProfile.id},}, 
        );
    

    const hashPassword = bcrypt.hashSync(password, 8);
    const userPassword = await users.update({
        password: hashPassword
    }, {where: {id: dataProfile.id}})    

    return res.status(201).send({
        message: "Profile updated!"
    })
}

// Delete Account Service!
const deleteUser = async (req, res) => {
    const token = req.headers['authorization']
    const dataProfile = jwt.verify(token.split(" ")[1], process.env.JWT_SECRET);

    const deleteProfile = await users.destroy({where: {id: dataProfile.id}});

    return res.status(201).send({
        message:"User deleted!"
    })
        
};


// Get Data Profiles User by user authorization!
const userProfile = async(req, res) => {
    const token = req.headers['authorization']
    const dataProfile = jwt.verify(token.split(" ")[1], process.env.JWT_SECRET);
    
    const usersData = await users.findOne({where: {id: dataProfile.id}});

    return res.status(200).send({
        message: "User info retrieved!",
        data: usersData
    })
};

module.exports = { register, userProfile, deleteUser, updateProfile, loginUser }