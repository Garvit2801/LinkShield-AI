"""Run: python -m evals.run_eval   (needs GOOGLE_CLOUD_PROJECT + credentials). Expand claims.jsonl to 30-50 verified claims."""
import asyncio, json, sys

from app import pipeline


async def main(path="evals/claims.jsonl"):
    rows = [json.loads(l) for l in open(path, encoding="utf-8") if l.strip()]
    sem = asyncio.Semaphore(4)

    async def one(r):
        async with sem:
            try:
                res = await pipeline.check_claim(r["claim"], r.get("lang", "en"))
                return {**r, "got": res["verdict"], "conf": res["confidence"], "grounded": res["grounded"]}
            except Exception as e:
                return {**r, "got": "error", "conf": 0.0, "grounded": False, "err": str(e)[:120]}

    out = await asyncio.gather(*[one(r) for r in rows])
    ok = sum(o["got"] == o["expected"] for o in out)
    print(f"accuracy {ok}/{len(out)} = {ok/len(out):.0%}")
    for o in out:
        print("PASS" if o["got"] == o["expected"] else "FAIL", o["expected"], "->", o["got"], f'{o["conf"]:.2f}', o["claim"][:60])
    with open("evals/results.json", "w", encoding="utf-8") as f:
        json.dump(out, f, ensure_ascii=False, indent=2)


if __name__ == "__main__":
    asyncio.run(main(*sys.argv[1:]))
