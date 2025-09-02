// handler.js
const AWS = require('aws-sdk');
const dynamoDB = new AWS.DynamoDB.DocumentClient();
const bcrypt = require('bcrypt');

module.exports.register = async (event) => {
    const data = JSON.parse(event.body);

    // Validate user input
    if (!data.userId || !data.password) {
        return { statusCode: 400, body: JSON.stringify({ message: 'User ID and password are required' }) }; 
    }

    const hashedPassword = await bcrypt.hash(data.password, 10);

    const params = {
        TableName: 'Users',
        Item: {
            userId: data.userId,
            password: hashedPassword,
            // Other user information
        }
    };

    try {
        await dynamoDB.put(params).promise();
        console.log(`User registered: ${data.userId} at ${new Date().toISOString()}`);
        return { statusCode: 200, body: JSON.stringify({ message: 'User registered successfully' }) };
    } catch (error) {
        console.error('Error registering user:', error);
        return { statusCode: 500, body: JSON.stringify({ message: 'Could not register user' }) };
    }
};

module.exports.login = async (event) => {
    const data = JSON.parse(event.body);

    // Validate user input
    if (!data.userId || !data.password) {
        return { statusCode: 400, body: JSON.stringify({ message: 'User ID and password are required' }) }; 
    }

    const params = {
        TableName: 'Users',
        Key: { userId: data.userId }
    };

    try {
        const result = await dynamoDB.get(params).promise();
        if (result.Item && await bcrypt.compare(data.password, result.Item.password)) {
            return { statusCode: 200, body: JSON.stringify({ message: 'Login successful' }) };
        } else {
            return { statusCode: 401, body: JSON.stringify({ message: 'Invalid username or password' }) };
        }
    } catch (error) {
        console.error('Error logging in user:', error);
        return { statusCode: 500, body: JSON.stringify({ message: 'Could not login user' }) };
    }
};

module.exports.getUser = async (event) => {
    const userId = event.pathParameters.id;
    const params = {
        TableName: 'Users',
        Key: { userId }
    };
    try {
        const result = await dynamoDB.get(params).promise();
        return { statusCode: 200, body: JSON.stringify(result.Item) };
    } catch (error) {
        console.error('Error retrieving user:', error);
        return { statusCode: 500, body: JSON.stringify({ message: 'Could not retrieve user' }) };
    }
};

module.exports.managePermissions = async (event) => {
    // Permission management logic
    return { statusCode: 200, body: JSON.stringify({ message: 'Permission management successful' }) };
};