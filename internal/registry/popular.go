package registry

import "strings"

// popular lists well-known packages per ecosystem. A name one typo away
// from one of these, that is not itself on the list, may be a typosquat.
// The list needs no network, so the check works when the registry does not
// answer. Names are in their normal form (PyPI: PEP 503).
var popular = map[Eco][]string{
	NPM: strings.Fields(`
react react-dom react-router react-router-dom react-redux redux next vue vue-router nuxt
svelte angular preact solid-js lit jquery lodash underscore ramda moment dayjs date-fns luxon
axios node-fetch got superagent express koa fastify hapi nestjs body-parser cors helmet
morgan cookie-parser multer passport jsonwebtoken bcrypt bcryptjs dotenv uuid nanoid chalk
commander yargs inquirer ora debug minimist glob rimraf mkdirp fs-extra chokidar nodemon
webpack vite rollup esbuild parcel babel-loader typescript ts-node tsx eslint prettier
jest mocha chai vitest cypress playwright puppeteer sinon supertest
mongoose sequelize prisma typeorm knex pg mysql mysql2 sqlite3 redis ioredis mongodb
socket.io socket.io-client ws graphql apollo-server zod yup joi ajv classnames clsx
tailwindcss postcss autoprefixer sass styled-components emotion bootstrap
three d3 chart.js echarts rxjs immer zustand mobx jotai formik
electron sharp cheerio jsdom marked markdown-it highlight.js prismjs
openai langchain dotenv-expand cross-env concurrently husky lint-staged
`),
	PyPI: strings.Fields(`
requests urllib3 httpx aiohttp certifi idna charset-normalizer
numpy pandas scipy matplotlib seaborn plotly scikit-learn tensorflow keras torch torchvision
transformers datasets tokenizers accelerate openai anthropic langchain tiktoken
flask django fastapi uvicorn gunicorn starlette pydantic sqlalchemy alembic psycopg2
psycopg2-binary pymysql redis celery boto3 botocore awscli google-cloud-storage
pyyaml toml tomli python-dotenv click typer rich tqdm colorama jinja2 markupsafe
pytest pytest-cov coverage tox nox black isort flake8 pylint mypy ruff pre-commit
setuptools wheel pip virtualenv poetry pipenv twine build cryptography pyjwt bcrypt
paramiko pillow opencv-python beautifulsoup4 lxml selenium scrapy playwright
python-dateutil pytz arrow attrs six packaging typing-extensions protobuf grpcio
pyarrow polars dask numba sympy networkx nltk spacy gensim xgboost lightgbm
`),
	Crates: strings.Fields(`
serde serde_json serde_yaml tokio async-std futures reqwest hyper axum actix-web warp rocket
clap structopt anyhow thiserror log env_logger tracing tracing-subscriber rand regex
lazy_static once_cell chrono time uuid itertools rayon crossbeam parking_lot bytes
sqlx diesel rusqlite redis base64 sha2 ring rustls openssl url http tower tonic prost
syn quote proc-macro2 libc nix walkdir tempfile glob indicatif dialoguer toml ripgrep
`),
}

var popularSet = func() map[Eco]map[string]bool {
	m := map[Eco]map[string]bool{}
	for eco, names := range popular {
		m[eco] = map[string]bool{}
		for _, n := range names {
			m[eco][n] = true
		}
	}
	return m
}()

// Lookalike returns the popular package that name looks like: one edit
// (insert, delete, change, or swap of two neighbours) away, or the same
// after separators are dropped ("reactdom" for "react-dom"). Short names
// are skipped: too many real packages are one edit apart.
func Lookalike(eco Eco, name string) (string, bool) {
	name = strings.ToLower(name)
	if popularSet[eco][name] {
		return "", false
	}
	bare := strings.TrimPrefix(name, "@")
	if i := strings.IndexByte(bare, '/'); i >= 0 {
		return "", false // scoped npm names belong to their scope's owner
	}
	if len(bare) < 5 {
		return "", false
	}
	flat := stripSeps(bare)
	for _, p := range popular[eco] {
		if len(p) < 5 {
			continue
		}
		if stripSeps(p) == flat || oneEdit(bare, p) {
			return p, true
		}
	}
	return "", false
}

func stripSeps(s string) string {
	return strings.NewReplacer("-", "", "_", "", ".", "").Replace(s)
}

// oneEdit: a and b differ by one insert, delete, change, or swap of two
// neighbouring characters.
func oneEdit(a, b string) bool {
	if a == b {
		return false
	}
	la, lb := len(a), len(b)
	if la-lb > 1 || lb-la > 1 {
		return false
	}
	i := 0
	for i < la && i < lb && a[i] == b[i] {
		i++
	}
	switch {
	case la == lb:
		if a[i+1:] == b[i+1:] {
			return true // change
		}
		return i+1 < la && a[i] == b[i+1] && a[i+1] == b[i] && a[i+2:] == b[i+2:] // swap
	case la > lb:
		return a[i+1:] == b[i:]
	default:
		return a[i:] == b[i+1:]
	}
}
