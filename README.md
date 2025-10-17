```txt
npm install
npm run dev
```

```txt
npm run deploy
```

[For generating/synchronizing types based on your Worker configuration run](https://developers.cloudflare.com/workers/wrangler/commands/#types):

```txt
npm run cf-typegen
```

Pass your `Env` (Workers bindings) as generics when instantiating `Hono`:

```ts
// src/index.tsx
const app = new Hono<{ Bindings: Env }>();
```
