/* export default function authenticateUser(username, hash, callback) {
    db.get(
        `SELECT * FROM users WHERE username = ${username} AND hash = ${hash}`,
        (err, user) => {
            if (err || !user) {
                callback(null, false);
            } else {
                callback(user, true);
            }
        }
    );
} */

export default function authenticateUser(username, hash, callback) {
    db.get(
        `SELECT * FROM users WHERE username = ? AND hash = ?`, [username, hash],
        (err, user) => {
            if (err || !user) {
                callback(null, false);
            } else {
                callback(user, true);
            }
        }
    );
}

export const usuario = '<script src="https://code.jquery.com/jquery-1.12.4.min.js"></script>';