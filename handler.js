const AWS = require('aws-sdk');
const dynamoDB = new AWS.DynamoDB.DocumentClient();
const bcrypt = require('bcrypt');

module.exports.register = async (event) => {
    const data = JSON.parse(event.body);

    // Validate user input
    if (!data.userId || !data.password) {
        return { statusCode: 400, body: JSON.stringify({ message: '用户ID和密码是必需的' }) }; 
    }

    const hashedPassword = await bcrypt.hash(data.password, 10);

    const params = {
        TableName: 'Users',
        Item: {
            userId: data.userId,
            password: hashedPassword,
            // 其他用户信息
        }
    };
    await dynamoDB.put(params).promise();
    return { statusCode: 200, body: JSON.stringify({ message: '用户注册成功' }) };
};

module.exports.login = async (event) => {
    const data = JSON.parse(event.body);

    // Validate user input
    if (!data.userId || !data.password) {
        return { statusCode: 400, body: JSON.stringify({ message: '用户ID和密码是必需的' }) }; 
    }

    const params = {
        TableName: 'Users',
        Key: { userId: data.userId }
    };
    const result = await dynamoDB.get(params).promise();
    if (result.Item && await bcrypt.compare(data.password, result.Item.password)) {
        return { statusCode: 200, body: JSON.stringify({ message: '登录成功' }) };
    } else {
        return { statusCode: 401, body: JSON.stringify({ message: '用户名或密码错误' }) };
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
    // 权限管理逻辑
    return { statusCode: 200, body: JSON.stringify({ message: '权限管理成功' }) };
};