const express = require('express');
const { register, deleteUser, updateProfile, loginUser, userProfile } = require('../controllers/user.controller');
const verifyToken = require('../middlewares/verifiedToken');


const router = express.Router();

// router.delete('/delete/:id', deleteUser);
// router.put('/editProfile/:id', updateProfile);
router.post('/register', register);
router.post('/login', loginUser);
router.get('/profile',verifyToken, userProfile);
router.delete('/delete',verifyToken, deleteUser);
router.put('/update',verifyToken, updateProfile);
// router.get('/all', allUsers);



module.exports = router;