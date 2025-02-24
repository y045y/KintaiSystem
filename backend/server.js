const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const bodyParser = require('body-parser');
require('dotenv').config();  // .envファイルの読み込み
const sql = require('mssql');
const jwt = require('jsonwebtoken');

const app = express();
const port = process.env.PORT || 5000;

// DB接続情報
const config = {
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  server: process.env.DB_SERVER,
  database: process.env.DB_DATABASE,
  port: parseInt(process.env.DB_PORT, 10),
  options: {
    encrypt: false,
    enableArithAbort: true
  }
};

app.use(cors());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization']; // 修正: 変数が未定義だったのを追加
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ message: 'トークンがありません' });
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) {
      return res.status(403).json({ message: '認証に失敗しました' });
    }
    req.user = decoded; // ユーザー情報をリクエストに格納
    next();
  });
};

app.get('/api/attendance-status', authenticateToken, async (req, res) => {
  try {
    // データベース接続
    const pool = await sql.connect(config);
    const userId = req.user.id;
    const today = new Date().toISOString().split('T')[0];

    // クエリ実行
    const result = await pool.request()
      .input('userId', sql.Int, userId)
      .input('today', sql.Date, today)
      .query(`
        SELECT clockIn, clockOut 
        FROM AttendanceRecords 
        WHERE userId = @userId AND workDate = @today
      `);

    // 出勤情報をレスポンスに返す
    if (result.recordset.length > 0) {
      const { clockIn, clockOut } = result.recordset[0];
      res.status(200).json({
        isClockedIn: !!clockIn,  // `true` または `false`
        isClockedOut: !!clockOut
      });
    } else {
      res.status(200).json({
        isClockedIn: false,
        isClockedOut: false
      });
    }
  } catch (err) {
    console.error('出勤状況取得エラー:', err);
    res.status(500).json({ message: 'サーバーエラーが発生しました。' });
  }
});
// ログイン処理（認証）
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;

  try {
    const pool = await sql.connect(config);
    const result = await pool.request()
      .input('email', sql.NVarChar, email)
      .query('SELECT id, email, userName, password FROM EmployeeMaster WHERE email = @email');

    if (result.recordset.length > 0) {
      const user = result.recordset[0];

      // パスワードが一致するか確認
      const passwordMatch = await bcrypt.compare(password, user.password);
      if (passwordMatch) {
        // トークンを発行
        const token = jwt.sign({ id: user.id }, process.env.JWT_SECRET, { expiresIn: '1h' });
        res.status(200).json({ token, user: { id: user.id, userName: user.userName, email: user.email } });
      } else {
        res.status(401).json({ message: 'パスワードが間違っています' });
      }
    } else {
      res.status(404).json({ message: 'ユーザーが見つかりません' });
    }
  } catch (err) {
    console.error('ログインエラー:', err);
    res.status(500).json({ message: 'サーバーエラー' });
  }
});

// ユーザー登録エンドポイント
app.post('/api/register', async (req, res) => {
  const { email, userName, password } = req.body;

  try {
    const pool = await sql.connect(config);

    // 既に同じメールアドレスのユーザーがいないかチェック
    const checkResult = await pool.request()
      .input('email', sql.NVarChar, email)
      .query('SELECT id FROM EmployeeMaster WHERE email = @email');

    if (checkResult.recordset.length > 0) {
      return res.status(400).json({ message: '既にこのメールアドレスは使用されています' });
    }

    // パスワードをハッシュ化
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    // ユーザーを登録
    await pool.request()
      .input('email', sql.NVarChar, email)
      .input('userName', sql.NVarChar, userName)
      .input('password', sql.NVarChar, hashedPassword)
      .query(`
        INSERT INTO EmployeeMaster (email, userName, salary, paidLeaveTotal, paidLeaveRemaining, createdAt, updatedAt, password)
        VALUES (@email, @userName, 0, 20, 20, GETDATE(), GETDATE(), @password)
      `);

    res.status(200).json({ message: 'ユーザー登録が完了しました' });
  } catch (error) {
    console.error('ユーザー登録エラー:', error);
    res.status(500).json({ message: 'サーバーエラー' });
  }
});

// ユーザー情報を取得するAPI（JWT認証）
app.get('/api/user', async (req, res) => {
  const authHeader = req.headers['authorization'];
  
  // トークンがあるか確認
  if (!authHeader) {
    console.warn('🚨 Authorization Header がありません');
    return res.status(401).json({ message: 'トークンがありません' });
  }

  const token = authHeader.split(' ')[1];
  console.log('🔍 Authorization Header:', authHeader);

  try {
    // JWTトークンの検証
    if (!process.env.JWT_SECRET) {
      console.error('❌ 環境変数 JWT_SECRET が設定されていません');
      return res.status(500).json({ message: 'サーバーエラー: JWT_SECRET 未設定' });
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    console.log('✅ トークン検証成功:', decoded);

    const pool = await sql.connect(config);
    const result = await pool.request()
      .input('userId', sql.Int, decoded.id)
      .query('SELECT id, email, userName FROM EmployeeMaster WHERE id = @userId');

    if (result.recordset.length > 0) {
      console.log('👤 ユーザー情報取得成功:', result.recordset[0]);
      return res.status(200).json(result.recordset[0]);
    } else {
      console.warn('⚠ ユーザーが見つかりません:', decoded.id);
      return res.status(404).json({ message: 'ユーザーが見つかりません' });
    }
  } catch (err) {
    if (err.name === 'TokenExpiredError') {
      console.warn('⏳ JWTトークンが期限切れです:', err);
      return res.status(401).json({ message: 'トークンが期限切れです。再ログインしてください。' });
    }

    if (err.name === 'JsonWebTokenError') {
      console.warn('🚫 無効なJWTトークン:', err);
      return res.status(403).json({ message: '認証に失敗しました: 無効なトークン' });
    }

    console.error('⚠ JWT検証またはDBエラー:', err);
    return res.status(500).json({ message: 'サーバーエラー' });
  }
});


// ✅ 必要な他のエンドポイントにも `authenticateToken` を適用
app.post('/api/clockin', authenticateToken, async (req, res) => {
  const { clockInTime, workDate } = req.body; 

  try {
    const pool = await sql.connect(config);
    const userId = req.user.id;

    // 🔹 workDate が送信されていなかった場合、今日の日付をデフォルトに設定
    const workDateFinal = workDate ? workDate : new Date().toISOString().split('T')[0];

    // トランザクション開始
    const transaction = new sql.Transaction(pool);
    await transaction.begin();

    try {
      const request = new sql.Request(transaction);
      await request
        .input('userId', sql.Int, userId)
        .input('workDate', sql.Date, workDateFinal)  // ✅ workDate を適切にセット
        .input('clockIn', sql.DateTime, clockInTime)
        .query(`
          INSERT INTO AttendanceRecords (
            userId, workDate, clockIn, clockOut, noBreak, overtimeMinutes, holidayOvertimeMinutes, notes, createdAt, updatedAt
          )
          VALUES (
            @userId, @workDate, @clockIn, NULL, 0, 0, 0, '出勤', GETDATE(), GETDATE()
          )
        `);

      await transaction.commit();
      res.status(200).json({ message: '出勤情報が記録されました' });
    } catch (err) {
      if (transaction._aborted !== true) {
        await transaction.rollback();
      }
      console.error('トランザクションエラー:', err);
      res.status(500).json({ message: '出勤情報の記録に失敗しました' });
    }
  } catch (error) {
    console.error('clockinエンドポイントエラー:', error);
    res.status(500).json({ message: 'サーバーエラー' });
  }
});


// ✅ 退勤APIにも適用
app.post('/api/clockout', authenticateToken, async (req, res) => {
  const { clockOutTime, noBreak } = req.body;

  try {
    const pool = await sql.connect(config);
    const userId = req.user?.id;

    if (!userId) {
      return res.status(403).json({ message: '認証エラー：ユーザー情報が取得できません' });
    }

    const today = new Date().toISOString().split('T')[0]; // 今日の日付 (YYYY-MM-DD)

    // 本日の出勤記録を取得
    const recordResult = await pool.request()
      .input('userId', sql.Int, userId)
      .input('today', sql.Date, today)
      .query(`
        SELECT id FROM AttendanceRecords 
        WHERE userId = @userId AND workDate = @today
      `);

    if (recordResult.recordset.length === 0) {
      return res.status(404).json({ message: '本日の出勤記録が見つかりません' });
    }
    
    const recordId = recordResult.recordset[0].id;

    // トランザクション開始
    const transaction = new sql.Transaction(pool);
    await transaction.begin();

    try {
      const request = new sql.Request(transaction);
      await request
        .input('recordId', sql.Int, recordId)
        .input('clockOut', sql.DateTime, clockOutTime)
        .input('noBreak', sql.Bit, noBreak)
        .query(`
          UPDATE AttendanceRecords 
          SET clockOut = @clockOut, noBreak = @noBreak, updatedAt = GETDATE() 
          WHERE id = @recordId
        `);

      // コミット
      await transaction.commit();
      res.status(200).json({ message: '退勤情報が記録されました' });

    } catch (err) {
      // トランザクションがアクティブな場合のみロールバック
      if (transaction._aborted !== true) {
        await transaction.rollback();
      }
      console.error('トランザクションエラー:', err);
      res.status(500).json({ message: '退勤処理に失敗しました' });
    }

  } catch (error) {
    console.error('clockoutエンドポイントエラー:', error);
    res.status(500).json({ message: 'サーバーエラー' });
  }
});

app.post('/api/leave-request', authenticateToken, async (req, res) => {
  const { leaveDate, leaveType, reason } = req.body;
  const userId = req.user.id;

  if (!leaveDate || !leaveType || !reason) {
    return res.status(400).json({ message: 'すべての項目を入力してください' });
  }

  try {
    const pool = await sql.connect(config);

    await pool.request()
      .input('userId', sql.Int, userId)
      .input('leaveDate', sql.Date, leaveDate)
      .input('leaveType', sql.NVarChar, leaveType)
      .input('reason', sql.NVarChar, reason)
      .input('status', sql.NVarChar, '申請中')
      .input('approverEmail', sql.NVarChar, 'admin@company.com') // 仮の承認者メール
      .query(`
        INSERT INTO LeaveRequests (userId, leaveDate, leaveType, reason, status, approverEmail, createdAt, updatedAt)
        VALUES (@userId, @leaveDate, @leaveType, @reason, @status, @approverEmail, GETDATE(), GETDATE())
      `);

    res.status(201).json({ message: '休暇申請が作成されました' });
  } catch (error) {
    console.error('休暇申請エラー:', error);
    res.status(500).json({ message: 'サーバーエラー' });
  }
});

app.get('/api/leave-requests', authenticateToken, async (req, res) => {
  try {
    const pool = await sql.connect(config);
    const userId = req.user.id;

    const result = await pool.request()
      .input('userId', sql.Int, userId)
      .query(`
        SELECT id, leaveDate, leaveType, reason, status, approverEmail, createdAt, updatedAt
        FROM LeaveRequests
        WHERE userId = @userId
      `);

    res.status(200).json(result.recordset);
  } catch (error) {
    console.error('休暇一覧取得エラー:', error);
    res.status(500).json({ message: 'サーバーエラー' });
  }
});

app.patch('/api/leave-request/:id', authenticateToken, async (req, res) => {
  const { status } = req.body;  // "承認" または "却下"
  const requestId = req.params.id;

  if (!['承認', '却下'].includes(status)) {
    return res.status(400).json({ message: '無効なステータスです' });
  }

  try {
    const pool = await sql.connect(config);

    await pool.request()
      .input('requestId', sql.Int, requestId)
      .input('status', sql.NVarChar, status)
      .query(`
        UPDATE LeaveRequests 
        SET status = @status, updatedAt = GETDATE() 
        WHERE id = @requestId
      `);

    res.status(200).json({ message: `休暇申請が${status}されました` });
  } catch (error) {
    console.error('休暇申請更新エラー:', error);
    res.status(500).json({ message: 'サーバーエラー' });
  }
});

app.get('/api/admin/leave-requests', authenticateToken, async (req, res) => {
  try {
    const pool = await sql.connect(config);

    const result = await pool.request().query(`
      SELECT lr.id, lr.leaveDate, lr.leaveType, lr.reason, lr.status, 
             lr.createdAt, lr.updatedAt, em.userName, em.email
      FROM LeaveRequests lr
      JOIN EmployeeMaster em ON lr.userId = em.id
      ORDER BY lr.leaveDate DESC
    `);

    res.status(200).json(result.recordset);
  } catch (err) {
    console.error('管理者用休暇申請取得エラー:', err);
    res.status(500).json({ message: '管理者用休暇申請の取得に失敗しました' });
  }
});

app.put('/api/admin/leave-requests/:id', authenticateToken, async (req, res) => {
  const { id } = req.params;
  const { status } = req.body; // "承認" or "却下"

  try {
    const pool = await sql.connect(config);

    const result = await pool.request()
      .input('id', sql.Int, id)
      .input('status', sql.NVarChar, status)
      .query(`
        UPDATE LeaveRequests
        SET status = @status, updatedAt = GETDATE()
        WHERE id = @id
      `);

    if (result.rowsAffected[0] > 0) {
      res.status(200).json({ message: `申請 ${id} を ${status} に更新しました` });
    } else {
      res.status(404).json({ message: '該当の申請が見つかりません' });
    }
  } catch (err) {
    console.error('休暇申請更新エラー:', err);
    res.status(500).json({ message: '休暇申請の更新に失敗しました' });
  }
});


// サーバーの起動
app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});
