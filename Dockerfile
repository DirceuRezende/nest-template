FROM node:alpine

WORKDIR /usr/app

COPY package.json ./

COPY yarn.lock ./

RUN yarn

COPY . .

RUN yarn build

RUN npx prisma generate

EXPOSE 3001

CMD ["yarn", "dev"]