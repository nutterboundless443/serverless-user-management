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
    await dynamoDB.put(params).promise();
    console.log(`User registered: ${data.userId} at ${new Date().toISOString()}`); // Added logging for user registration with timestamp
    return { statusCode: 200, body: JSON.stringify({ message: 'User registered successfully' }) };
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
    const result = await dynamoDB.get(params).promise();
    if (result.Item && await bcrypt.compare(data.password, result.Item.password)) {
        return { statusCode: 200, body: JSON.stringify({ message: 'Login successful' }) };
    } else {
        return { statusCode: 401, body: JSON.stringify({ message: 'Invalid username or password' }) };
    }
};

module.exports.getUser = async (event) => {
    const userId = event.pathParameters.id;
    const params = {
        TableName: 'Users',
        Key: { userId }
    };
    const result = await dynamoDB.get(params).promise();
    return { statusCode: 200, body: JSON.stringify(result.Item) };
};

module.exports.managePermissions = async (event) => {
    // Permission management logic
    return { statusCode: 200, body: JSON.stringify({ message: 'Permission management successful' }) };
};