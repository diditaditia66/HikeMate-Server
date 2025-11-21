
/* =========================================
 * Routes
 * =======================================*/

// PUBLIC: health
app.get('/api/health', (_req, res) => res.json({ ok: true, message: 'HikeMate API is healthy 🚀' }));

// Semua endpoint di bawah ini butuh login
app.use('/api', authRequired);

// LIST Trips (milik user yang login)
app.get('/api/trips', async (req, res) => {
  try {
    const trips = await Trip.findAll({
      where: { ownerSub: req.auth.sub },
      order: [['createdAt', 'DESC']],
    });

    const shaped = trips.map((t) => ({
      id: t.id,
      name: t.name,
      startDate: t.startDate,
      endDate: t.endDate,
      dateRange: t.dateRange || toDateRangeString(t.startDate, t.endDate),
      participants: t.participants || [],
      participantsCount: t.participants?.length || t.participantsCount || 0,
      createdAt: t.createdAt,
      updatedAt: t.updatedAt,
    }));
    res.json(shaped);
  } catch (err) {
    console.error('Error fetching trips:', err);
    res.status(500).json({ error: 'Failed to fetch trips' });
  }
});

// DETAIL Trip (hanya milik user)
app.get('/api/trips/:tripId', async (req, res) => {
  try {
    const id = parseInt(req.params.tripId, 10);
    const check = await assertTripOwned(id, req.auth.sub);
    if (check.error) return res.status(check.status).json({ error: check.error });
    const t = check.trip;

    res.json({
      id: t.id,
      name: t.name,
      startDate: t.startDate,
      endDate: t.endDate,
      dateRange: t.dateRange || toDateRangeString(t.startDate, t.endDate),
      participants: t.participants || [],
      participantsCount: t.participants?.length || t.participantsCount || 0,
      createdAt: t.createdAt,
      updatedAt: t.updatedAt,
    });
  } catch (err) {
    console.error('Error fetching trip detail:', err);
    res.status(500).json({ error: 'Failed to fetch trip' });
  }
});

// CREATE Trip (catat owner dari token)
app.post('/api/trips', async (req, res) => {
  try {
    const { name, startDate, endDate, dateRange, participants, participantsCount } = req.body;
    if (!name) return res.status(400).json({ error: 'name is required' });

    const created = await Trip.create({
      ownerSub: req.auth.sub,
      ownerEmail: req.auth.email || null,
      ownerName: req.auth.name || null,

      name,
      startDate: startDate || null,
      endDate: endDate || null,
      dateRange: dateRange || null,
      participants: Array.isArray(participants) ? participants : [],
      participantsCount: participantsCount ?? (Array.isArray(participants) ? participants.length : 0),
    });

    res.status(201).json({
      id: created.id,
      name: created.name,
      startDate: created.startDate,
      endDate: created.endDate,
      dateRange: created.dateRange || toDateRangeString(created.startDate, created.endDate),
      participants: created.participants || [],
      participantsCount: created.participants?.length || created.participantsCount || 0,
      createdAt: created.createdAt,
      updatedAt: created.updatedAt,
    });
  } catch (err) {
    console.error('Error creating trip:', err);
    res.status(500).json({ error: 'Failed to create trip' });
  }
});

// LOGISTICS (list)
app.get('/api/trips/:tripId/logistics', async (req, res) => {
  try {
    const { tripId } = req.params;
    const check = await assertTripOwned(tripId, req.auth.sub);
    if (check.error) return res.status(check.status).json({ error: check.error });

    const items = await Logistic.findAll({
      where: { TripId: tripId },
      order: [['createdAt', 'DESC']],
    });
    res.json(items);
  } catch (err) {
    console.error('Error fetching logistics:', err);
    res.status(500).json({ error: 'Failed to fetch logistics' });
  }
});

// CREATE Logistic
app.post('/api/trips/:tripId/logistics', async (req, res) => {
  try {
    const { tripId } = req.params;
    const { name, quantity, unit, description, price } = req.body;

    if (!name) return res.status(400).json({ error: 'name is required' });
    if (quantity != null && Number(quantity) < 1)
      return res.status(400).json({ error: 'quantity must be >= 1' });
    if (price != null && Number(price) < 0)
      return res.status(400).json({ error: 'price must be >= 0' });

    const check = await assertTripOwned(tripId, req.auth.sub);
    if (check.error) return res.status(check.status).json({ error: check.error });

    const created = await Logistic.create({
      TripId: tripId,
      name,
      quantity: quantity ?? 1,
      unit: unit || 'unit',
      description: description || '',
      price: price ?? 0,
    });

    res.status(201).json(created);
  } catch (err) {
    console.error('Error creating logistic:', err);
    res.status(500).json({ error: 'Failed to create logistic' });
  }
});

// UPDATE Logistic
app.put('/api/trips/:tripId/logistics/:logId', async (req, res) => {
  try {
    const { tripId, logId } = req.params;
    const { name, quantity, unit, description, price } = req.body;

    const check = await assertTripOwned(tripId, req.auth.sub);
    if (check.error) return res.status(check.status).json({ error: check.error });

    const row = await Logistic.findOne({ where: { id: logId, TripId: tripId } });
    if (!row) return res.status(404).json({ error: 'Logistic not found' });

    if (name != null && String(name).trim() === '') {
      return res.status(400).json({ error: 'name cannot be empty' });
    }
    if (quantity != null && Number(quantity) < 1) {
      return res.status(400).json({ error: 'quantity must be >= 1' });
    }
    if (price != null && Number(price) < 0) {
      return res.status(400).json({ error: 'price must be >= 0' });
    }

    await row.update({
      name: name ?? row.name,
      quantity: quantity ?? row.quantity,
      unit: unit ?? row.unit,
      description: description ?? row.description,
      price: price ?? row.price,
    });

    res.json(row);
  } catch (err) {
    console.error('Error updating logistic:', err);
    res.status(500).json({ error: 'Failed to update logistic' });
  }
});

// DELETE Logistic
app.delete('/api/trips/:tripId/logistics/:logId', async (req, res) => {
  try {
    const { tripId, logId } = req.params;

    const check = await assertTripOwned(tripId, req.auth.sub);
    if (check.error) return res.status(check.status).json({ error: check.error });

    const row = await Logistic.findOne({ where: { id: logId, TripId: tripId } });
    if (!row) return res.status(404).json({ error: 'Logistic not found' });

    await row.destroy();
    res.json({ ok: true });
  } catch (err) {
    console.error('Error deleting logistic:', err);
    res.status(500).json({ error: 'Failed to delete logistic' });
  }
});

// COST SUMMARY
// GET /api/trips/:tripId/cost-summary?people=5
app.get('/api/trips/:tripId/cost-summary', async (req, res) => {
  try {
    const { tripId } = req.params;
    const peopleParam = parseInt(String(req.query.people || ''), 10);

    const check = await assertTripOwned(tripId, req.auth.sub);
    if (check.error) return res.status(check.status).json({ error: check.error });

    const [trip, items] = await Promise.all([
      Trip.findByPk(tripId),
      Logistic.findAll({ where: { TripId: tripId } }),
    ]);

    const total = items.reduce((s, it) => {
      const qty = Number(it.quantity) || 0;
      const price = Number(it.price) || 0;
      return s + qty * price;
    }, 0);

    const basePeople =
      Number.isFinite(peopleParam) && peopleParam > 0
        ? peopleParam
        : (trip?.participants?.length || trip?.participantsCount || 1);

    const perPerson = basePeople > 0 ? Math.round(total / basePeople) : total;

    res.json({
      tripId: Number(tripId),
      people: basePeople,
      total,
      perPerson,
      currency: 'IDR',
    });
  } catch (err) {
    console.error('Error cost summary:', err);
    res.status(500).json({ error: 'Failed to get cost summary' });
  }
});


// ROP (list)
app.get('/api/trips/:tripId/rop', async (req, res) => {
  try {
    const { tripId } = req.params;
    const check = await assertTripOwned(tripId, req.auth.sub);
    if (check.error) return res.status(check.status).json({ error: check.error });

    const items = await ROP.findAll({
      where: { TripId: tripId },
      order: [
        ['date', 'ASC'],
        ['startTime', 'ASC'],
        ['createdAt', 'ASC'],
      ],
    });
    res.json(items);
  } catch (err) {
    console.error('Error fetching ROP:', err);
    res.status(500).json({ error: 'Failed to fetch ROP' });
  }
});

// ROP (create)
app.post('/api/trips/:tripId/rop', async (req, res) => {
  try {
    const { tripId } = req.params;
    let { date, activity, personInCharge, startTime, endTime, notes, time } = req.body;

    if (!date || !activity) {
      return res.status(400).json({ error: 'date and activity are required' });
    }

    // Kompat lama: "YYYY-MM-DD HH:mm"
    if (typeof date === 'string' && date.includes(' ')) {
      const [d, t] = date.split(' ');
      date = d;
      if (!startTime) startTime = t;
    }
    if (!startTime && time) startTime = time;

    const check = await assertTripOwned(tripId, req.auth.sub);
    if (check.error) return res.status(check.status).json({ error: check.error });

    const created = await ROP.create({
      TripId: tripId,
      date,
      startTime: startTime || null,
      endTime: endTime || null,
      activity,
      personInCharge: personInCharge || '',
      notes: notes || '',
    });

    res.status(201).json(created);
  } catch (err) {
    console.error('Error creating ROP:', err);
    res.status(500).json({ error: 'Failed to create ROP' });
  }
});

// UPDATE ROP (opsional)
app.put('/api/trips/:tripId/rop/:ropId', async (req, res) => {
  try {
    const { tripId, ropId } = req.params;
    const { date, startTime, endTime, activity, personInCharge, notes } = req.body;

    const check = await assertTripOwned(tripId, req.auth.sub);
    if (check.error) return res.status(check.status).json({ error: check.error });

    const row = await ROP.findOne({ where: { id: ropId, TripId: tripId } });
    if (!row) return res.status(404).json({ error: 'ROP not found' });

    if (activity != null && String(activity).trim() === '') {
      return res.status(400).json({ error: 'activity cannot be empty' });
    }
    await row.update({
      date: date ?? row.date,
      startTime: startTime ?? row.startTime,
      endTime: endTime ?? row.endTime,
      activity: activity ?? row.activity,
      personInCharge: personInCharge ?? row.personInCharge,
      notes: notes ?? row.notes,
    });

    res.json(row);
  } catch (err) {
    console.error('Error updating ROP:', err);
    res.status(500).json({ error: 'Failed to update ROP' });
  }
});

// DELETE ROP
app.delete('/api/trips/:tripId/rop/:ropId', async (req, res) => {
  try {
    const { tripId, ropId } = req.params;

    const check = await assertTripOwned(tripId, req.auth.sub);
    if (check.error) return res.status(check.status).json({ error: check.error });

    const row = await ROP.findOne({ where: { id: ropId, TripId: tripId } });
    if (!row) return res.status(404).json({ error: 'ROP not found' });

    await row.destroy();
    res.json({ ok: true });
  } catch (err) {
    console.error('Error deleting ROP:', err);
    res.status(500).json({ error: 'Failed to delete ROP' });
  }
});


// 404
app.use((_req, res) => res.status(404).json({ error: 'Route not found' }));

const PORT = process.env.PORT || 3000;
const HOST = '0.0.0.0';

(async () => {
  try {
    await sequelize.authenticate();
    console.log('Database connected');
    await sequelize.sync({ alter: true }); // menambah kolom baru bila perlu
    console.log('Models synced');
    app.listen(PORT, HOST, () => console.log(`Server running on http://${HOST}:${PORT}`));
  } catch (err) {
    console.error('Failed to start server:', err);
    process.exit(1);
  }
})();

EOF

node server.js
pm2 restart hikemate-api
cat .env
console.log(process.env);
ls
cd config
ls
cd ~hikemate-api
cd ~/hikemate-api
ls
nano .env
node server.js
pm2 restart hikemate-api
pm2 list
pm2 logs hikemate-api
pm2 logs hikemate-api --err
cat > server.js <<'EOF'
'use strict';
const express = require('express');
const cors = require('cors');
const morgan = require('morgan');
const { DataTypes, Op } = require('sequelize');
const sequelize = require('./config/database');
// jose harus diimpor secara dinamis (karena ESM)
let jose;
(async () => {
  jose = await import('jose');
})();

const {
  COGNITO_REGION = 'ap-northeast-3',
  COGNITO_USER_POOL_ID = 'ap-northeast-3_uo0e0XP3a',
  COGNITO_CLIENT_ID = 'ccjs4bf1tgndab95t09m3sotd',
} = process.env;

if (!COGNITO_USER_POOL_ID) {
  console.warn('[WARN] COGNITO_USER_POOL_ID belum di-set. Set di env agar verifikasi JWT tepat.');
}

const app = express();
app.use(cors());
app.use(express.json({ limit: '1mb' }));
app.use(morgan('tiny'));
app.disable('x-powered-by');

/* =========================================
 * Auth (Cognito JWT verification)
 * =======================================*/
const issuer = `https://cognito-idp.${COGNITO_REGION}.amazonaws.com/${COGNITO_USER_POOL_ID}`;
async function getJwks() {
  if (!jose) jose = await import('jose');
  return jose.createRemoteJWKSet(new URL(`${issuer}/.well-known/jwks.json`));
}

async function verifyToken(bearer) {
  if (!bearer || !bearer.startsWith('Bearer '))
    throw Object.assign(new Error('Missing token'), { status: 401 });

  const token = bearer.slice('Bearer '.length);
  const { jwtVerify } = jose || (await import('jose'));
  const jwks = await getJwks();

  const { payload } = await jwtVerify(token, jwks, {
    issuer,
    audience: COGNITO_CLIENT_ID || undefined,
  });

  if (payload.token_use && !['id', 'access'].includes(payload.token_use)) {
    throw Object.assign(new Error('Invalid token_use'), { status: 401 });
  }

  return {
    sub: payload.sub,
    email: payload.email,
    name: payload.name || payload.given_name || payload['custom:name'] || null,
    payload,
  };
}

async function authRequired(req, res, next) {
  try {
    const info = await verifyToken(req.headers.authorization || '');
    req.auth = info; // {sub,email,name}
    next();
  } catch (err) {
    const code = err.status || 401;
    res.status(code).json({ error: 'Unauthorized', detail: err.message || 'Invalid token' });
  }
}

/* =========================================
 * Models
 * =======================================*/
const Trip = sequelize.define(
  'Trip',
  {
    // owner (pemilik data)
    ownerSub: { type: DataTypes.STRING, allowNull: false },              // Cognito sub
    ownerEmail: { type: DataTypes.STRING, allowNull: true },
    ownerName: { type: DataTypes.STRING, allowNull: true },

    name: { type: DataTypes.STRING, allowNull: false },
    startDate: { type: DataTypes.DATEONLY, allowNull: true },
    endDate: { type: DataTypes.DATEONLY, allowNull: true },
    dateRange: { type: DataTypes.STRING, allowNull: true },
    participantsCount: { type: DataTypes.INTEGER, allowNull: true },
    participants: { type: DataTypes.JSONB, allowNull: true, defaultValue: [] },
  },
  { tableName: 'Trips', timestamps: true, indexes: [{ fields: ['ownerSub'] }] }
);

const Logistic = sequelize.define(
  'Logistic',
  {
    name:        { type: DataTypes.STRING,  allowNull: false },
    quantity:    { type: DataTypes.INTEGER, allowNull: false, defaultValue: 1 },
    unit:        { type: DataTypes.STRING,  allowNull: true,  defaultValue: 'unit' },
    description: { type: DataTypes.STRING,  allowNull: true },
    price:       { type: DataTypes.INTEGER, allowNull: false, defaultValue: 0 },
  },
  { tableName: 'Logistics', timestamps: true }
);

const ROP = sequelize.define(
  'ROP',
  {
    date: { type: DataTypes.STRING, allowNull: false },
    startTime: { type: DataTypes.STRING, allowNull: true },
    endTime: { type: DataTypes.STRING, allowNull: true },
    activity: { type: DataTypes.STRING, allowNull: false },
    personInCharge: { type: DataTypes.STRING, allowNull: true },
    notes: { type: DataTypes.STRING, allowNull: true },
  },
  { tableName: 'RopItems', timestamps: true }
);

// Relasi
Trip.hasMany(Logistic, { as: 'logistics', foreignKey: { name: 'TripId', allowNull: false }, onDelete: 'CASCADE' });
Logistic.belongsTo(Trip, { foreignKey: { name: 'TripId', allowNull: false } });

Trip.hasMany(ROP, { as: 'ropItems', foreignKey: { name: 'TripId', allowNull: false }, onDelete: 'CASCADE' });
ROP.belongsTo(Trip, { foreignKey: { name: 'TripId', allowNull: false } });

/* =========================================
 * Utils
 * =======================================*/
const toDateRangeString = (startDate, endDate) => {
  if (!startDate && !endDate) return '';
  if (startDate && !endDate) return startDate;
  if (!startDate && endDate) return endDate;
  return `${startDate} s/d ${endDate}`;
};

async function assertTripOwned(tripId, ownerSub) {
  const t = await Trip.findByPk(tripId);
  if (!t) return { status: 404, error: 'Trip not found' };
  if (t.ownerSub !== ownerSub) return { status: 403, error: 'Forbidden' };
  return { trip: t };
}

/* =========================================
 * Routes
 * =======================================*/

// PUBLIC: health
app.get('/api/health', (_req, res) => res.json({ ok: true, message: 'HikeMate API is healthy 🚀' }));

// Semua endpoint di bawah ini butuh login
app.use('/api', authRequired);

// LIST Trips (milik user yang login)
app.get('/api/trips', async (req, res) => {
  try {
    const trips = await Trip.findAll({
      where: { ownerSub: req.auth.sub },
      order: [['createdAt', 'DESC']],
    });

    const shaped = trips.map((t) => ({
      id: t.id,
      name: t.name,
      startDate: t.startDate,
      endDate: t.endDate,
      dateRange: t.dateRange || toDateRangeString(t.startDate, t.endDate),
      participants: t.participants || [],
      participantsCount: t.participants?.length || t.participantsCount || 0,
      createdAt: t.createdAt,
      updatedAt: t.updatedAt,
    }));
    res.json(shaped);
  } catch (err) {
    console.error('Error fetching trips:', err);
    res.status(500).json({ error: 'Failed to fetch trips' });
  }
});

// DETAIL Trip (hanya milik user)
app.get('/api/trips/:tripId', async (req, res) => {
  try {
    const id = parseInt(req.params.tripId, 10);
    const check = await assertTripOwned(id, req.auth.sub);
    if (check.error) return res.status(check.status).json({ error: check.error });
    const t = check.trip;

    res.json({
      id: t.id,
      name: t.name,
      startDate: t.startDate,
      endDate: t.endDate,
      dateRange: t.dateRange || toDateRangeString(t.startDate, t.endDate),
      participants: t.participants || [],
      participantsCount: t.participants?.length || t.participantsCount || 0,
      createdAt: t.createdAt,
      updatedAt: t.updatedAt,
    });
  } catch (err) {
    console.error('Error fetching trip detail:', err);
    res.status(500).json({ error: 'Failed to fetch trip' });
  }
});

// CREATE Trip (catat owner dari token)
app.post('/api/trips', async (req, res) => {
  try {
    const { name, startDate, endDate, dateRange, participants, participantsCount } = req.body;
    if (!name) return res.status(400).json({ error: 'name is required' });

    const created = await Trip.create({
      ownerSub: req.auth.sub,
      ownerEmail: req.auth.email || null,
      ownerName: req.auth.name || null,

      name,
      startDate: startDate || null,
      endDate: endDate || null,
      dateRange: dateRange || null,
      participants: Array.isArray(participants) ? participants : [],
      participantsCount: participantsCount ?? (Array.isArray(participants) ? participants.length : 0),
    });

    res.status(201).json({
      id: created.id,
      name: created.name,
      startDate: created.startDate,
      endDate: created.endDate,
      dateRange: created.dateRange || toDateRangeString(created.startDate, created.endDate),
      participants: created.participants || [],
      participantsCount: created.participants?.length || created.participantsCount || 0,
      createdAt: created.createdAt,
      updatedAt: created.updatedAt,
    });
  } catch (err) {
    console.error('Error creating trip:', err);
    res.status(500).json({ error: 'Failed to create trip' });
  }
});

// LOGISTICS (list)
app.get('/api/trips/:tripId/logistics', async (req, res) => {
  try {
    const { tripId } = req.params;
    const check = await assertTripOwned(tripId, req.auth.sub);
    if (check.error) return res.status(check.status).json({ error: check.error });

    const items = await Logistic.findAll({
      where: { TripId: tripId },
      order: [['createdAt', 'DESC']],
    });
    res.json(items);
  } catch (err) {
    console.error('Error fetching logistics:', err);
    res.status(500).json({ error: 'Failed to fetch logistics' });
  }
});

// CREATE Logistic
app.post('/api/trips/:tripId/logistics', async (req, res) => {
  try {
    const { tripId } = req.params;
    const { name, quantity, unit, description, price } = req.body;

    if (!name) return res.status(400).json({ error: 'name is required' });
    if (quantity != null && Number(quantity) < 1)
      return res.status(400).json({ error: 'quantity must be >= 1' });
    if (price != null && Number(price) < 0)
      return res.status(400).json({ error: 'price must be >= 0' });

    const check = await assertTripOwned(tripId, req.auth.sub);
    if (check.error) return res.status(check.status).json({ error: check.error });

    const created = await Logistic.create({
      TripId: tripId,
      name,
      quantity: quantity ?? 1,
      unit: unit || 'unit',
      description: description || '',
      price: price ?? 0,
    });

    res.status(201).json(created);
  } catch (err) {
    console.error('Error creating logistic:', err);
    res.status(500).json({ error: 'Failed to create logistic' });
  }
});

// UPDATE Logistic
app.put('/api/trips/:tripId/logistics/:logId', async (req, res) => {
  try {
    const { tripId, logId } = req.params;
    const { name, quantity, unit, description, price } = req.body;

    const check = await assertTripOwned(tripId, req.auth.sub);
    if (check.error) return res.status(check.status).json({ error: check.error });

    const row = await Logistic.findOne({ where: { id: logId, TripId: tripId } });
    if (!row) return res.status(404).json({ error: 'Logistic not found' });

    if (name != null && String(name).trim() === '') {
      return res.status(400).json({ error: 'name cannot be empty' });
    }
    if (quantity != null && Number(quantity) < 1) {
      return res.status(400).json({ error: 'quantity must be >= 1' });
    }
    if (price != null && Number(price) < 0) {
      return res.status(400).json({ error: 'price must be >= 0' });
    }

    await row.update({
      name: name ?? row.name,
      quantity: quantity ?? row.quantity,
      unit: unit ?? row.unit,
      description: description ?? row.description,
      price: price ?? row.price,
    });

    res.json(row);
  } catch (err) {
    console.error('Error updating logistic:', err);
    res.status(500).json({ error: 'Failed to update logistic' });
  }
});

// DELETE Logistic
app.delete('/api/trips/:tripId/logistics/:logId', async (req, res) => {
  try {
    const { tripId, logId } = req.params;

    const check = await assertTripOwned(tripId, req.auth.sub);
    if (check.error) return res.status(check.status).json({ error: check.error });

    const row = await Logistic.findOne({ where: { id: logId, TripId: tripId } });
    if (!row) return res.status(404).json({ error: 'Logistic not found' });

    await row.destroy();
    res.json({ ok: true });
  } catch (err) {
    console.error('Error deleting logistic:', err);
    res.status(500).json({ error: 'Failed to delete logistic' });
  }
});

// COST SUMMARY
// GET /api/trips/:tripId/cost-summary?people=5
app.get('/api/trips/:tripId/cost-summary', async (req, res) => {
  try {
    const { tripId } = req.params;
    const peopleParam = parseInt(String(req.query.people || ''), 10);

    const check = await assertTripOwned(tripId, req.auth.sub);
    if (check.error) return res.status(check.status).json({ error: check.error });

    const [trip, items] = await Promise.all([
      Trip.findByPk(tripId),
      Logistic.findAll({ where: { TripId: tripId } }),
    ]);

    const total = items.reduce((s, it) => {
      const qty = Number(it.quantity) || 0;
      const price = Number(it.price) || 0;
      return s + qty * price;
    }, 0);

    const basePeople =
      Number.isFinite(peopleParam) && peopleParam > 0
        ? peopleParam
        : (trip?.participants?.length || trip?.participantsCount || 1);

    const perPerson = basePeople > 0 ? Math.round(total / basePeople) : total;

    res.json({
      tripId: Number(tripId),
      people: basePeople,
      total,
      perPerson,
      currency: 'IDR',
    });
  } catch (err) {
    console.error('Error cost summary:', err);
    res.status(500).json({ error: 'Failed to get cost summary' });
  }
});


// ROP (list)
app.get('/api/trips/:tripId/rop', async (req, res) => {
  try {
    const { tripId } = req.params;
    const check = await assertTripOwned(tripId, req.auth.sub);
    if (check.error) return res.status(check.status).json({ error: check.error });

    const items = await ROP.findAll({
      where: { TripId: tripId },
      order: [
        ['date', 'ASC'],
        ['startTime', 'ASC'],
        ['createdAt', 'ASC'],
      ],
    });
    res.json(items);
  } catch (err) {
    console.error('Error fetching ROP:', err);
    res.status(500).json({ error: 'Failed to fetch ROP' });
  }
});

// ROP (create)
app.post('/api/trips/:tripId/rop', async (req, res) => {
  try {
    const { tripId } = req.params;
    let { date, activity, personInCharge, startTime, endTime, notes, time } = req.body;

    if (!date || !activity) {
      return res.status(400).json({ error: 'date and activity are required' });
    }

    // Kompat lama: "YYYY-MM-DD HH:mm"
    if (typeof date === 'string' && date.includes(' ')) {
      const [d, t] = date.split(' ');
      date = d;
      if (!startTime) startTime = t;
    }
    if (!startTime && time) startTime = time;

    const check = await assertTripOwned(tripId, req.auth.sub);
    if (check.error) return res.status(check.status).json({ error: check.error });

    const created = await ROP.create({
      TripId: tripId,
      date,
      startTime: startTime || null,
      endTime: endTime || null,
      activity,
      personInCharge: personInCharge || '',
      notes: notes || '',
    });

    res.status(201).json(created);
  } catch (err) {
    console.error('Error creating ROP:', err);
    res.status(500).json({ error: 'Failed to create ROP' });
  }
});

// UPDATE ROP (opsional)
app.put('/api/trips/:tripId/rop/:ropId', async (req, res) => {
  try {
    const { tripId, ropId } = req.params;
    const { date, startTime, endTime, activity, personInCharge, notes } = req.body;

    const check = await assertTripOwned(tripId, req.auth.sub);
    if (check.error) return res.status(check.status).json({ error: check.error });

    const row = await ROP.findOne({ where: { id: ropId, TripId: tripId } });
    if (!row) return res.status(404).json({ error: 'ROP not found' });

    if (activity != null && String(activity).trim() === '') {
      return res.status(400).json({ error: 'activity cannot be empty' });
    }
    await row.update({
      date: date ?? row.date,
      startTime: startTime ?? row.startTime,
      endTime: endTime ?? row.endTime,
      activity: activity ?? row.activity,
      personInCharge: personInCharge ?? row.personInCharge,
      notes: notes ?? row.notes,
    });

    res.json(row);
  } catch (err) {
    console.error('Error updating ROP:', err);
    res.status(500).json({ error: 'Failed to update ROP' });
  }
});

// DELETE ROP
app.delete('/api/trips/:tripId/rop/:ropId', async (req, res) => {
  try {
    const { tripId, ropId } = req.params;

    const check = await assertTripOwned(tripId, req.auth.sub);
    if (check.error) return res.status(check.status).json({ error: check.error });

    const row = await ROP.findOne({ where: { id: ropId, TripId: tripId } });
    if (!row) return res.status(404).json({ error: 'ROP not found' });

    await row.destroy();
    res.json({ ok: true });
  } catch (err) {
    console.error('Error deleting ROP:', err);
    res.status(500).json({ error: 'Failed to delete ROP' });
  }
});


// 404
app.use((_req, res) => res.status(404).json({ error: 'Route not found' }));

const PORT = process.env.PORT || 3000;
const HOST = '0.0.0.0';

(async () => {
  try {
    await sequelize.authenticate();
    console.log('Database connected');
    await sequelize.sync({ alter: true }); // menambah kolom baru bila perlu
    console.log('Models synced');
    app.listen(PORT, HOST, () => console.log(`Server running on http://${HOST}:${PORT}`));
  } catch (err) {
    console.error('Failed to start server:', err);
    process.exit(1);
  }
})();

EOF

pm2 restart hikemate-api
cd hikemate-api
node -v
cat > server.js <<'EOF'
'use strict';
const express = require('express');
const cors = require('cors');
const morgan = require('morgan');
const { DataTypes, Op } = require('sequelize');
const sequelize = require('./config/database');
const { webcrypto } = require('node:crypto');
if (!globalThis.crypto) globalThis.crypto = webcrypto;
// jose harus diimpor secara dinamis (karena ESM)
let jose;
(async () => {
  jose = await import('jose');
})();

const {
  COGNITO_REGION = 'ap-northeast-3',
  COGNITO_USER_POOL_ID = 'ap-northeast-3_uo0e0XP3a',
  COGNITO_CLIENT_ID = 'ccjs4bf1tgndab95t09m3sotd',
} = process.env;

if (!COGNITO_USER_POOL_ID) {
  console.warn('[WARN] COGNITO_USER_POOL_ID belum di-set. Set di env agar verifikasi JWT tepat.');
}

const app = express();
app.use(cors());
app.use(express.json({ limit: '1mb' }));
app.use(morgan('tiny'));
app.disable('x-powered-by');

/* =========================================
 * Auth (Cognito JWT verification)
 * =======================================*/
const issuer = `https://cognito-idp.${COGNITO_REGION}.amazonaws.com/${COGNITO_USER_POOL_ID}`;
async function getJwks() {
  if (!jose) jose = await import('jose');
  return jose.createRemoteJWKSet(new URL(`${issuer}/.well-known/jwks.json`));
}

async function verifyToken(bearer) {
  if (!bearer || !bearer.startsWith('Bearer '))
    throw Object.assign(new Error('Missing token'), { status: 401 });

  const token = bearer.slice('Bearer '.length);
  const { jwtVerify } = jose || (await import('jose'));
  const jwks = await getJwks();

  const { payload } = await jwtVerify(token, jwks, {
    issuer,
    audience: COGNITO_CLIENT_ID || undefined,
  });

  if (payload.token_use && !['id', 'access'].includes(payload.token_use)) {
    throw Object.assign(new Error('Invalid token_use'), { status: 401 });
  }

  return {
    sub: payload.sub,
    email: payload.email,
    name: payload.name || payload.given_name || payload['custom:name'] || null,
    payload,
  };
}

async function authRequired(req, res, next) {
  try {
    const info = await verifyToken(req.headers.authorization || '');
    req.auth = info; // {sub,email,name}
    next();
  } catch (err) {
    const code = err.status || 401;
    res.status(code).json({ error: 'Unauthorized', detail: err.message || 'Invalid token' });
  }
}

/* =========================================
 * Models
 * =======================================*/
const Trip = sequelize.define(
  'Trip',
  {
    // owner (pemilik data)
    ownerSub: { type: DataTypes.STRING, allowNull: false },              // Cognito sub
    ownerEmail: { type: DataTypes.STRING, allowNull: true },
    ownerName: { type: DataTypes.STRING, allowNull: true },

    name: { type: DataTypes.STRING, allowNull: false },
    startDate: { type: DataTypes.DATEONLY, allowNull: true },
    endDate: { type: DataTypes.DATEONLY, allowNull: true },
    dateRange: { type: DataTypes.STRING, allowNull: true },
    participantsCount: { type: DataTypes.INTEGER, allowNull: true },
    participants: { type: DataTypes.JSONB, allowNull: true, defaultValue: [] },
  },
  { tableName: 'Trips', timestamps: true, indexes: [{ fields: ['ownerSub'] }] }
);

const Logistic = sequelize.define(
  'Logistic',
  {
    name:        { type: DataTypes.STRING,  allowNull: false },
    quantity:    { type: DataTypes.INTEGER, allowNull: false, defaultValue: 1 },
    unit:        { type: DataTypes.STRING,  allowNull: true,  defaultValue: 'unit' },
    description: { type: DataTypes.STRING,  allowNull: true },
    price:       { type: DataTypes.INTEGER, allowNull: false, defaultValue: 0 },
  },
  { tableName: 'Logistics', timestamps: true }
);

const ROP = sequelize.define(
  'ROP',
  {
    date: { type: DataTypes.STRING, allowNull: false },
    startTime: { type: DataTypes.STRING, allowNull: true },
    endTime: { type: DataTypes.STRING, allowNull: true },
    activity: { type: DataTypes.STRING, allowNull: false },
    personInCharge: { type: DataTypes.STRING, allowNull: true },
    notes: { type: DataTypes.STRING, allowNull: true },
  },
  { tableName: 'RopItems', timestamps: true }
);

// Relasi
Trip.hasMany(Logistic, { as: 'logistics', foreignKey: { name: 'TripId', allowNull: false }, onDelete: 'CASCADE' });
Logistic.belongsTo(Trip, { foreignKey: { name: 'TripId', allowNull: false } });

Trip.hasMany(ROP, { as: 'ropItems', foreignKey: { name: 'TripId', allowNull: false }, onDelete: 'CASCADE' });
ROP.belongsTo(Trip, { foreignKey: { name: 'TripId', allowNull: false } });

/* =========================================
 * Utils
 * =======================================*/
const toDateRangeString = (startDate, endDate) => {
  if (!startDate && !endDate) return '';
  if (startDate && !endDate) return startDate;
  if (!startDate && endDate) return endDate;
  return `${startDate} s/d ${endDate}`;
};

async function assertTripOwned(tripId, ownerSub) {
  const t = await Trip.findByPk(tripId);
  if (!t) return { status: 404, error: 'Trip not found' };
  if (t.ownerSub !== ownerSub) return { status: 403, error: 'Forbidden' };
  return { trip: t };
}

/* =========================================
 * Routes
 * =======================================*/

// PUBLIC: health
app.get('/api/health', (_req, res) => res.json({ ok: true, message: 'HikeMate API is healthy 🚀' }));

// Semua endpoint di bawah ini butuh login
app.use('/api', authRequired);

// LIST Trips (milik user yang login)
app.get('/api/trips', async (req, res) => {
  try {
    const trips = await Trip.findAll({
      where: { ownerSub: req.auth.sub },
      order: [['createdAt', 'DESC']],
    });

    const shaped = trips.map((t) => ({
      id: t.id,
      name: t.name,
      startDate: t.startDate,
      endDate: t.endDate,
      dateRange: t.dateRange || toDateRangeString(t.startDate, t.endDate),
      participants: t.participants || [],
      participantsCount: t.participants?.length || t.participantsCount || 0,
      createdAt: t.createdAt,
      updatedAt: t.updatedAt,
    }));
    res.json(shaped);
  } catch (err) {
    console.error('Error fetching trips:', err);
    res.status(500).json({ error: 'Failed to fetch trips' });
  }
});

// DETAIL Trip (hanya milik user)
app.get('/api/trips/:tripId', async (req, res) => {
  try {
    const id = parseInt(req.params.tripId, 10);
    const check = await assertTripOwned(id, req.auth.sub);
    if (check.error) return res.status(check.status).json({ error: check.error });
    const t = check.trip;

    res.json({
      id: t.id,
      name: t.name,
      startDate: t.startDate,
      endDate: t.endDate,
      dateRange: t.dateRange || toDateRangeString(t.startDate, t.endDate),
      participants: t.participants || [],
      participantsCount: t.participants?.length || t.participantsCount || 0,
      createdAt: t.createdAt,
      updatedAt: t.updatedAt,
    });
  } catch (err) {
    console.error('Error fetching trip detail:', err);
    res.status(500).json({ error: 'Failed to fetch trip' });
  }
});

// CREATE Trip (catat owner dari token)
app.post('/api/trips', async (req, res) => {
  try {
    const { name, startDate, endDate, dateRange, participants, participantsCount } = req.body;
    if (!name) return res.status(400).json({ error: 'name is required' });

    const created = await Trip.create({
      ownerSub: req.auth.sub,
      ownerEmail: req.auth.email || null,
      ownerName: req.auth.name || null,

      name,
      startDate: startDate || null,
      endDate: endDate || null,
      dateRange: dateRange || null,
      participants: Array.isArray(participants) ? participants : [],
      participantsCount: participantsCount ?? (Array.isArray(participants) ? participants.length : 0),
    });

    res.status(201).json({
      id: created.id,
      name: created.name,
      startDate: created.startDate,
      endDate: created.endDate,
      dateRange: created.dateRange || toDateRangeString(created.startDate, created.endDate),
      participants: created.participants || [],
      participantsCount: created.participants?.length || created.participantsCount || 0,
      createdAt: created.createdAt,
      updatedAt: created.updatedAt,
    });
  } catch (err) {
    console.error('Error creating trip:', err);
    res.status(500).json({ error: 'Failed to create trip' });
  }
});

// LOGISTICS (list)
app.get('/api/trips/:tripId/logistics', async (req, res) => {
  try {
    const { tripId } = req.params;
    const check = await assertTripOwned(tripId, req.auth.sub);
    if (check.error) return res.status(check.status).json({ error: check.error });

    const items = await Logistic.findAll({
      where: { TripId: tripId },
      order: [['createdAt', 'DESC']],
    });
    res.json(items);
  } catch (err) {
    console.error('Error fetching logistics:', err);
    res.status(500).json({ error: 'Failed to fetch logistics' });
  }
});

// CREATE Logistic
app.post('/api/trips/:tripId/logistics', async (req, res) => {
  try {
    const { tripId } = req.params;
    const { name, quantity, unit, description, price } = req.body;

    if (!name) return res.status(400).json({ error: 'name is required' });
    if (quantity != null && Number(quantity) < 1)
      return res.status(400).json({ error: 'quantity must be >= 1' });
    if (price != null && Number(price) < 0)
      return res.status(400).json({ error: 'price must be >= 0' });

    const check = await assertTripOwned(tripId, req.auth.sub);
    if (check.error) return res.status(check.status).json({ error: check.error });

    const created = await Logistic.create({
      TripId: tripId,
      name,
      quantity: quantity ?? 1,
      unit: unit || 'unit',
      description: description || '',
      price: price ?? 0,
    });

    res.status(201).json(created);
  } catch (err) {
    console.error('Error creating logistic:', err);
    res.status(500).json({ error: 'Failed to create logistic' });
  }
});

// UPDATE Logistic
app.put('/api/trips/:tripId/logistics/:logId', async (req, res) => {
  try {
    const { tripId, logId } = req.params;
    const { name, quantity, unit, description, price } = req.body;

    const check = await assertTripOwned(tripId, req.auth.sub);
    if (check.error) return res.status(check.status).json({ error: check.error });

    const row = await Logistic.findOne({ where: { id: logId, TripId: tripId } });
    if (!row) return res.status(404).json({ error: 'Logistic not found' });

    if (name != null && String(name).trim() === '') {
      return res.status(400).json({ error: 'name cannot be empty' });
    }
    if (quantity != null && Number(quantity) < 1) {
      return res.status(400).json({ error: 'quantity must be >= 1' });
    }
    if (price != null && Number(price) < 0) {
      return res.status(400).json({ error: 'price must be >= 0' });
    }

    await row.update({
      name: name ?? row.name,
      quantity: quantity ?? row.quantity,
      unit: unit ?? row.unit,
      description: description ?? row.description,
      price: price ?? row.price,
    });

    res.json(row);
  } catch (err) {
    console.error('Error updating logistic:', err);
    res.status(500).json({ error: 'Failed to update logistic' });
  }
});

// DELETE Logistic
app.delete('/api/trips/:tripId/logistics/:logId', async (req, res) => {
  try {
    const { tripId, logId } = req.params;

    const check = await assertTripOwned(tripId, req.auth.sub);
    if (check.error) return res.status(check.status).json({ error: check.error });

    const row = await Logistic.findOne({ where: { id: logId, TripId: tripId } });
    if (!row) return res.status(404).json({ error: 'Logistic not found' });

    await row.destroy();
    res.json({ ok: true });
  } catch (err) {
    console.error('Error deleting logistic:', err);
    res.status(500).json({ error: 'Failed to delete logistic' });
  }
});

// COST SUMMARY
// GET /api/trips/:tripId/cost-summary?people=5
app.get('/api/trips/:tripId/cost-summary', async (req, res) => {
  try {
    const { tripId } = req.params;
    const peopleParam = parseInt(String(req.query.people || ''), 10);

    const check = await assertTripOwned(tripId, req.auth.sub);
    if (check.error) return res.status(check.status).json({ error: check.error });

    const [trip, items] = await Promise.all([
      Trip.findByPk(tripId),
      Logistic.findAll({ where: { TripId: tripId } }),
    ]);

    const total = items.reduce((s, it) => {
      const qty = Number(it.quantity) || 0;
      const price = Number(it.price) || 0;
      return s + qty * price;
    }, 0);

    const basePeople =
      Number.isFinite(peopleParam) && peopleParam > 0
        ? peopleParam
        : (trip?.participants?.length || trip?.participantsCount || 1);

    const perPerson = basePeople > 0 ? Math.round(total / basePeople) : total;

    res.json({
      tripId: Number(tripId),
      people: basePeople,
      total,
      perPerson,
      currency: 'IDR',
    });
  } catch (err) {
    console.error('Error cost summary:', err);
    res.status(500).json({ error: 'Failed to get cost summary' });
  }
});


// ROP (list)
app.get('/api/trips/:tripId/rop', async (req, res) => {
  try {
    const { tripId } = req.params;
    const check = await assertTripOwned(tripId, req.auth.sub);
    if (check.error) return res.status(check.status).json({ error: check.error });

    const items = await ROP.findAll({
      where: { TripId: tripId },
      order: [
        ['date', 'ASC'],
        ['startTime', 'ASC'],
        ['createdAt', 'ASC'],
      ],
    });
    res.json(items);
  } catch (err) {
    console.error('Error fetching ROP:', err);
    res.status(500).json({ error: 'Failed to fetch ROP' });
  }
});

// ROP (create)
app.post('/api/trips/:tripId/rop', async (req, res) => {
  try {
    const { tripId } = req.params;
    let { date, activity, personInCharge, startTime, endTime, notes, time } = req.body;

    if (!date || !activity) {
      return res.status(400).json({ error: 'date and activity are required' });
    }

    // Kompat lama: "YYYY-MM-DD HH:mm"
    if (typeof date === 'string' && date.includes(' ')) {
      const [d, t] = date.split(' ');
      date = d;
      if (!startTime) startTime = t;
    }
    if (!startTime && time) startTime = time;

    const check = await assertTripOwned(tripId, req.auth.sub);
    if (check.error) return res.status(check.status).json({ error: check.error });

    const created = await ROP.create({
      TripId: tripId,
      date,
      startTime: startTime || null,
      endTime: endTime || null,
      activity,
      personInCharge: personInCharge || '',
      notes: notes || '',
    });

    res.status(201).json(created);
  } catch (err) {
    console.error('Error creating ROP:', err);
    res.status(500).json({ error: 'Failed to create ROP' });
  }
});

// UPDATE ROP (opsional)
app.put('/api/trips/:tripId/rop/:ropId', async (req, res) => {
  try {
    const { tripId, ropId } = req.params;
    const { date, startTime, endTime, activity, personInCharge, notes } = req.body;

    const check = await assertTripOwned(tripId, req.auth.sub);
    if (check.error) return res.status(check.status).json({ error: check.error });

    const row = await ROP.findOne({ where: { id: ropId, TripId: tripId } });
    if (!row) return res.status(404).json({ error: 'ROP not found' });

    if (activity != null && String(activity).trim() === '') {
      return res.status(400).json({ error: 'activity cannot be empty' });
    }
    await row.update({
      date: date ?? row.date,
      startTime: startTime ?? row.startTime,
      endTime: endTime ?? row.endTime,
      activity: activity ?? row.activity,
      personInCharge: personInCharge ?? row.personInCharge,
      notes: notes ?? row.notes,
    });

    res.json(row);
  } catch (err) {
    console.error('Error updating ROP:', err);
    res.status(500).json({ error: 'Failed to update ROP' });
  }
});

// DELETE ROP
app.delete('/api/trips/:tripId/rop/:ropId', async (req, res) => {
  try {
    const { tripId, ropId } = req.params;

    const check = await assertTripOwned(tripId, req.auth.sub);
    if (check.error) return res.status(check.status).json({ error: check.error });

    const row = await ROP.findOne({ where: { id: ropId, TripId: tripId } });
    if (!row) return res.status(404).json({ error: 'ROP not found' });

    await row.destroy();
    res.json({ ok: true });
  } catch (err) {
    console.error('Error deleting ROP:', err);
    res.status(500).json({ error: 'Failed to delete ROP' });
  }
});


// 404
app.use((_req, res) => res.status(404).json({ error: 'Route not found' }));

const PORT = process.env.PORT || 3000;
const HOST = '0.0.0.0';

(async () => {
  try {
    await sequelize.authenticate();
    console.log('Database connected');
    await sequelize.sync({ alter: true }); // menambah kolom baru bila perlu
    console.log('Models synced');
    app.listen(PORT, HOST, () => console.log(`Server running on http://${HOST}:${PORT}`));
  } catch (err) {
    console.error('Failed to start server:', err);
    process.exit(1);
  }
})();

EOF

pm2 restart hikemate-api
pm2 logs hikemate-api --lines 50
cat > server.js <<'EOF'
'use strict';
const express = require('express');
const cors = require('cors');
const morgan = require('morgan');
const { DataTypes, Op } = require('sequelize');
const sequelize = require('./config/database');
const { webcrypto } = require('node:crypto');
if (!globalThis.crypto) globalThis.crypto = webcrypto;
// jose harus diimpor secara dinamis (karena ESM)
let jose;
(async () => {
  jose = await import('jose');
})();

const {
  COGNITO_REGION = 'ap-northeast-3',
  COGNITO_USER_POOL_ID = 'ap-northeast-3_uo0e0XP3a',
  COGNITO_CLIENT_ID = 'ccjs4bf1tgndab95t09m3sotd',
} = process.env;

if (!COGNITO_USER_POOL_ID) {
  console.warn('[WARN] COGNITO_USER_POOL_ID belum di-set. Set di env agar verifikasi JWT tepat.');
}

const app = express();
app.use(cors());
app.use(express.json({ limit: '1mb' }));
app.use(morgan('tiny'));
app.disable('x-powered-by');

/* =========================================
 * Auth (Cognito JWT verification)
 * =======================================*/
const issuer = `https://cognito-idp.${COGNITO_REGION}.amazonaws.com/${COGNITO_USER_POOL_ID}`;
async function getJwks() {
  if (!jose) jose = await import('jose');
  return jose.createRemoteJWKSet(new URL(`${issuer}/.well-known/jwks.json`));
}

async function verifyToken(bearer) {
  if (!bearer || !bearer.startsWith('Bearer '))
    throw Object.assign(new Error('Missing token'), { status: 401 });

  const token = bearer.slice('Bearer '.length);
  const { jwtVerify } = jose || (await import('jose'));
  const jwks = await getJwks();

  const { payload } = await jwtVerify(token, jwks, {
    issuer,
    audience: COGNITO_CLIENT_ID || undefined,
  });

  if (payload.token_use && !['id', 'access'].includes(payload.token_use)) {
    throw Object.assign(new Error('Invalid token_use'), { status: 401 });
  }

  return {
    sub: payload.sub,
    email: payload.email,
    name: payload.name || payload.given_name || payload['custom:name'] || null,
    payload,
  };
}

async function authRequired(req, res, next) {
  try {
    const info = await verifyToken(req.headers.authorization || '');
    req.auth = info; // {sub,email,name}
    next();
  } catch (err) {
    const code = err.status || 401;
    res.status(code).json({ error: 'Unauthorized', detail: err.message || 'Invalid token' });
  }
}

/* =========================================
 * Models
 * =======================================*/
const Trip = sequelize.define(
  'Trip',
  {
    // owner (pemilik data)
    ownerSub: { type: DataTypes.STRING, allowNull: false },              // Cognito sub
    ownerEmail: { type: DataTypes.STRING, allowNull: true },
    ownerName: { type: DataTypes.STRING, allowNull: true },

    name: { type: DataTypes.STRING, allowNull: false },
    startDate: { type: DataTypes.DATEONLY, allowNull: true },
    endDate: { type: DataTypes.DATEONLY, allowNull: true },
    dateRange: { type: DataTypes.STRING, allowNull: true },
    participantsCount: { type: DataTypes.INTEGER, allowNull: true },
    participants: { type: DataTypes.JSONB, allowNull: true, defaultValue: [] },
  },
  { tableName: 'Trips', timestamps: true, indexes: [{ fields: ['ownerSub'] }] }
);

const Logistic = sequelize.define(
  'Logistic',
  {
    name:        { type: DataTypes.STRING,  allowNull: false },
    quantity:    { type: DataTypes.INTEGER, allowNull: false, defaultValue: 1 },
    unit:        { type: DataTypes.STRING,  allowNull: true,  defaultValue: 'unit' },
    description: { type: DataTypes.STRING,  allowNull: true },
    price:       { type: DataTypes.INTEGER, allowNull: false, defaultValue: 0 },
  },
  { tableName: 'Logistics', timestamps: true }
);

const ROP = sequelize.define(
  'ROP',
  {
    date: { type: DataTypes.STRING, allowNull: false },
    startTime: { type: DataTypes.STRING, allowNull: true },
    endTime: { type: DataTypes.STRING, allowNull: true },
    activity: { type: DataTypes.STRING, allowNull: false },
    personInCharge: { type: DataTypes.STRING, allowNull: true },
    notes: { type: DataTypes.STRING, allowNull: true },
  },
  { tableName: 'RopItems', timestamps: true }
);

// Relasi
Trip.hasMany(Logistic, { as: 'logistics', foreignKey: { name: 'TripId', allowNull: false }, onDelete: 'CASCADE' });
Logistic.belongsTo(Trip, { foreignKey: { name: 'TripId', allowNull: false } });

Trip.hasMany(ROP, { as: 'ropItems', foreignKey: { name: 'TripId', allowNull: false }, onDelete: 'CASCADE' });
ROP.belongsTo(Trip, { foreignKey: { name: 'TripId', allowNull: false } });

/* =========================================
 * Utils
 * =======================================*/
const toDateRangeString = (startDate, endDate) => {
  if (!startDate && !endDate) return '';
  if (startDate && !endDate) return startDate;
  if (!startDate && endDate) return endDate;
  return `${startDate} s/d ${endDate}`;
};

async function assertTripOwned(tripId, ownerSub) {
  const t = await Trip.findByPk(tripId);
  if (!t) return { status: 404, error: 'Trip not found' };
  if (t.ownerSub !== ownerSub) return { status: 403, error: 'Forbidden' };
  return { trip: t };
}

/* =========================================
 * Routes
 * =======================================*/

// PUBLIC: health
app.get('/api/health', (_req, res) => res.json({ ok: true, message: 'HikeMate API is healthy 🚀' }));

// Semua endpoint di bawah ini butuh login
app.use('/api', authRequired);

// LIST Trips (milik user yang login)
app.get('/api/trips', async (req, res) => {
  try {
    const trips = await Trip.findAll({
      where: { ownerSub: req.auth.sub },
      order: [['createdAt', 'DESC']],
    });

    const shaped = trips.map((t) => ({
      id: t.id,
      name: t.name,
      startDate: t.startDate,
      endDate: t.endDate,
      dateRange: t.dateRange || toDateRangeString(t.startDate, t.endDate),
      participants: t.participants || [],
      participantsCount: t.participants?.length || t.participantsCount || 0,
      createdAt: t.createdAt,
      updatedAt: t.updatedAt,
    }));
    res.json(shaped);
  } catch (err) {
    console.error('Error fetching trips:', err);
    res.status(500).json({ error: 'Failed to fetch trips' });
  }
});

// DETAIL Trip (hanya milik user)
app.get('/api/trips/:tripId', async (req, res) => {
  try {
    const id = parseInt(req.params.tripId, 10);
    const check = await assertTripOwned(id, req.auth.sub);
    if (check.error) return res.status(check.status).json({ error: check.error });
    const t = check.trip;

    res.json({
      id: t.id,
      name: t.name,
      startDate: t.startDate,
      endDate: t.endDate,
      dateRange: t.dateRange || toDateRangeString(t.startDate, t.endDate),
      participants: t.participants || [],
      participantsCount: t.participants?.length || t.participantsCount || 0,
      createdAt: t.createdAt,
      updatedAt: t.updatedAt,
    });
  } catch (err) {
    console.error('Error fetching trip detail:', err);
    res.status(500).json({ error: 'Failed to fetch trip' });
  }
});

// DELETE /api/trips/:tripId
app.delete('/api/trips/:tripId', async (req, res) => {
  try {
    const { tripId } = req.params;
    const check = await assertTripOwned(tripId, req.auth.sub);
    if (check.error) return res.status(check.status).json({ error: check.error });

    const trip = await Trip.findByPk(tripId);
    if (!trip) return res.status(404).json({ error: 'Trip not found' });

    await trip.destroy();
    res.json({ message: 'Trip deleted successfully' });
  } catch (err) {
    console.error('Error deleting trip:', err);
    res.status(500).json({ error: 'Failed to delete trip' });
  }
});

// CREATE Trip (catat owner dari token)
app.post('/api/trips', async (req, res) => {
  try {
    const { name, startDate, endDate, dateRange, participants, participantsCount } = req.body;
    if (!name) return res.status(400).json({ error: 'name is required' });

    const created = await Trip.create({
      ownerSub: req.auth.sub,
      ownerEmail: req.auth.email || null,
      ownerName: req.auth.name || null,

      name,
      startDate: startDate || null,
      endDate: endDate || null,
      dateRange: dateRange || null,
      participants: Array.isArray(participants) ? participants : [],
      participantsCount: participantsCount ?? (Array.isArray(participants) ? participants.length : 0),
    });

    res.status(201).json({
      id: created.id,
      name: created.name,
      startDate: created.startDate,
      endDate: created.endDate,
      dateRange: created.dateRange || toDateRangeString(created.startDate, created.endDate),
      participants: created.participants || [],
      participantsCount: created.participants?.length || created.participantsCount || 0,
      createdAt: created.createdAt,
      updatedAt: created.updatedAt,
    });
  } catch (err) {
    console.error('Error creating trip:', err);
    res.status(500).json({ error: 'Failed to create trip' });
  }
});

// LOGISTICS (list)
app.get('/api/trips/:tripId/logistics', async (req, res) => {
  try {
    const { tripId } = req.params;
    const check = await assertTripOwned(tripId, req.auth.sub);
    if (check.error) return res.status(check.status).json({ error: check.error });

    const items = await Logistic.findAll({
      where: { TripId: tripId },
      order: [['createdAt', 'DESC']],
    });
    res.json(items);
  } catch (err) {
    console.error('Error fetching logistics:', err);
    res.status(500).json({ error: 'Failed to fetch logistics' });
  }
});

// CREATE Logistic
app.post('/api/trips/:tripId/logistics', async (req, res) => {
  try {
    const { tripId } = req.params;
    const { name, quantity, unit, description, price } = req.body;

    if (!name) return res.status(400).json({ error: 'name is required' });
    if (quantity != null && Number(quantity) < 1)
      return res.status(400).json({ error: 'quantity must be >= 1' });
    if (price != null && Number(price) < 0)
      return res.status(400).json({ error: 'price must be >= 0' });

    const check = await assertTripOwned(tripId, req.auth.sub);
    if (check.error) return res.status(check.status).json({ error: check.error });

    const created = await Logistic.create({
      TripId: tripId,
      name,
      quantity: quantity ?? 1,
      unit: unit || 'unit',
      description: description || '',
      price: price ?? 0,
    });

    res.status(201).json(created);
  } catch (err) {
    console.error('Error creating logistic:', err);
    res.status(500).json({ error: 'Failed to create logistic' });
  }
});

// UPDATE Logistic
app.put('/api/trips/:tripId/logistics/:logId', async (req, res) => {
  try {
    const { tripId, logId } = req.params;
    const { name, quantity, unit, description, price } = req.body;

    const check = await assertTripOwned(tripId, req.auth.sub);
    if (check.error) return res.status(check.status).json({ error: check.error });

    const row = await Logistic.findOne({ where: { id: logId, TripId: tripId } });
    if (!row) return res.status(404).json({ error: 'Logistic not found' });

    if (name != null && String(name).trim() === '') {
      return res.status(400).json({ error: 'name cannot be empty' });
    }
    if (quantity != null && Number(quantity) < 1) {
      return res.status(400).json({ error: 'quantity must be >= 1' });
    }
    if (price != null && Number(price) < 0) {
      return res.status(400).json({ error: 'price must be >= 0' });
    }

    await row.update({
      name: name ?? row.name,
      quantity: quantity ?? row.quantity,
      unit: unit ?? row.unit,
      description: description ?? row.description,
      price: price ?? row.price,
    });

    res.json(row);
  } catch (err) {
    console.error('Error updating logistic:', err);
    res.status(500).json({ error: 'Failed to update logistic' });
  }
});

// DELETE Logistic
app.delete('/api/trips/:tripId/logistics/:logId', async (req, res) => {
  try {
    const { tripId, logId } = req.params;

    const check = await assertTripOwned(tripId, req.auth.sub);
    if (check.error) return res.status(check.status).json({ error: check.error });

    const row = await Logistic.findOne({ where: { id: logId, TripId: tripId } });
    if (!row) return res.status(404).json({ error: 'Logistic not found' });

    await row.destroy();
    res.json({ ok: true });
  } catch (err) {
    console.error('Error deleting logistic:', err);
    res.status(500).json({ error: 'Failed to delete logistic' });
  }
});

// COST SUMMARY
// GET /api/trips/:tripId/cost-summary?people=5
app.get('/api/trips/:tripId/cost-summary', async (req, res) => {
  try {
    const { tripId } = req.params;
    const peopleParam = parseInt(String(req.query.people || ''), 10);

    const check = await assertTripOwned(tripId, req.auth.sub);
    if (check.error) return res.status(check.status).json({ error: check.error });

    const [trip, items] = await Promise.all([
      Trip.findByPk(tripId),
      Logistic.findAll({ where: { TripId: tripId } }),
    ]);

    const total = items.reduce((s, it) => {
      const qty = Number(it.quantity) || 0;
      const price = Number(it.price) || 0;
      return s + qty * price;
    }, 0);

    const basePeople =
      Number.isFinite(peopleParam) && peopleParam > 0
        ? peopleParam
        : (trip?.participants?.length || trip?.participantsCount || 1);

    const perPerson = basePeople > 0 ? Math.round(total / basePeople) : total;

    res.json({
      tripId: Number(tripId),
      people: basePeople,
      total,
      perPerson,
      currency: 'IDR',
    });
  } catch (err) {
    console.error('Error cost summary:', err);
    res.status(500).json({ error: 'Failed to get cost summary' });
  }
});


// ROP (list)
app.get('/api/trips/:tripId/rop', async (req, res) => {
  try {
    const { tripId } = req.params;
    const check = await assertTripOwned(tripId, req.auth.sub);
    if (check.error) return res.status(check.status).json({ error: check.error });

    const items = await ROP.findAll({
      where: { TripId: tripId },
      order: [
        ['date', 'ASC'],
        ['startTime', 'ASC'],
        ['createdAt', 'ASC'],
      ],
    });
    res.json(items);
  } catch (err) {
    console.error('Error fetching ROP:', err);
    res.status(500).json({ error: 'Failed to fetch ROP' });
  }
});

// ROP (create)
app.post('/api/trips/:tripId/rop', async (req, res) => {
  try {
    const { tripId } = req.params;
    let { date, activity, personInCharge, startTime, endTime, notes, time } = req.body;

    if (!date || !activity) {
      return res.status(400).json({ error: 'date and activity are required' });
    }

    // Kompat lama: "YYYY-MM-DD HH:mm"
    if (typeof date === 'string' && date.includes(' ')) {
      const [d, t] = date.split(' ');
      date = d;
      if (!startTime) startTime = t;
    }
    if (!startTime && time) startTime = time;

    const check = await assertTripOwned(tripId, req.auth.sub);
    if (check.error) return res.status(check.status).json({ error: check.error });

    const created = await ROP.create({
      TripId: tripId,
      date,
      startTime: startTime || null,
      endTime: endTime || null,
      activity,
      personInCharge: personInCharge || '',
      notes: notes || '',
    });

    res.status(201).json(created);
  } catch (err) {
    console.error('Error creating ROP:', err);
    res.status(500).json({ error: 'Failed to create ROP' });
  }
});

// UPDATE ROP (opsional)
app.put('/api/trips/:tripId/rop/:ropId', async (req, res) => {
  try {
    const { tripId, ropId } = req.params;
    const { date, startTime, endTime, activity, personInCharge, notes } = req.body;

    const check = await assertTripOwned(tripId, req.auth.sub);
    if (check.error) return res.status(check.status).json({ error: check.error });

    const row = await ROP.findOne({ where: { id: ropId, TripId: tripId } });
    if (!row) return res.status(404).json({ error: 'ROP not found' });

    if (activity != null && String(activity).trim() === '') {
      return res.status(400).json({ error: 'activity cannot be empty' });
    }
    await row.update({
      date: date ?? row.date,
      startTime: startTime ?? row.startTime,
      endTime: endTime ?? row.endTime,
      activity: activity ?? row.activity,
      personInCharge: personInCharge ?? row.personInCharge,
      notes: notes ?? row.notes,
    });

    res.json(row);
  } catch (err) {
    console.error('Error updating ROP:', err);
    res.status(500).json({ error: 'Failed to update ROP' });
  }
});

// DELETE ROP
app.delete('/api/trips/:tripId/rop/:ropId', async (req, res) => {
  try {
    const { tripId, ropId } = req.params;

    const check = await assertTripOwned(tripId, req.auth.sub);
    if (check.error) return res.status(check.status).json({ error: check.error });

    const row = await ROP.findOne({ where: { id: ropId, TripId: tripId } });
    if (!row) return res.status(404).json({ error: 'ROP not found' });

    await row.destroy();
    res.json({ ok: true });
  } catch (err) {
    console.error('Error deleting ROP:', err);
    res.status(500).json({ error: 'Failed to delete ROP' });
  }
});


// 404
app.use((_req, res) => res.status(404).json({ error: 'Route not found' }));

const PORT = process.env.PORT || 3000;
const HOST = '0.0.0.0';

(async () => {
  try {
    await sequelize.authenticate();
    console.log('Database connected');
    await sequelize.sync({ alter: true }); // menambah kolom baru bila perlu
    console.log('Models synced');
    app.listen(PORT, HOST, () => console.log(`Server running on http://${HOST}:${PORT}`));
  } catch (err) {
    console.error('Failed to start server:', err);
    process.exit(1);
  }
})();


EOF

pm2 restart hikemate-api
ls
git status
git init
sudo -i
ls
sudo apt update
sudo apt install tree -y
ls
tree -L 2
tree -L 3
tree -L 2
git status
nano .gitignore
git status
cd hikemate-api
ls
tree -L 2
nano .gitignore
