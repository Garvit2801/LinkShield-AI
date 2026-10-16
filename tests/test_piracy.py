from app.security import piracy, signals


def score(url, page=None):
    return signals.classify(piracy.inspect(url, page) + [{"weight": 15}], [], "completed", True)


def test_known_piracy_brand_is_moderate_risk():
    page = {"title": "9xflix.com - Homepage", "final_url": "https://9xflix.fi/m/", "page_text": "", "behaviour": {"hosts": 32}}
    flags = piracy.inspect("https://9xflix.esq/m/", page)
    assert [f["code"] for f in flags] == ["piracy_site", "piracy_mirror"]
    assert "9xflix.esq to 9xflix.fi" in flags[1]["detail"]
    assert score("https://9xflix.esq/m/", page)[0] == "caution"
    # Even when the sandbox could not open the page, the name alone is enough.
    assert piracy.inspect("https://www.filmyzilla.lol/")[0]["code"] == "piracy_site"
    assert piracy.inspect("https://ww4.123movies.to/")[0]["code"] == "piracy_site"


def test_piracy_page_without_a_known_name():
    page = {"title": "NewFlix – Latest Bollywood movies", "page_text": "Jawan (2023) Hindi 1080p WEB-DL x264 2.4GB Dual Audio – Full Movie Download"}
    assert piracy.inspect("https://newflix.example/", page)[0]["code"] == "piracy_site"


def test_ordinary_movie_sites_are_not_flagged():
    review = {"title": "Jawan review", "page_text": "The film releases in theatres; the trailer is on YouTube in 1080p."}
    assert piracy.inspect("https://www.thehindu.com/entertainment/movies/jawan-review/", review) == []
    assert piracy.inspect("https://www.netflix.com/in/title/81234567", {"page_text": "Watch in 4K HDR. Download to watch offline."}) == []
    assert piracy.inspect("https://www.bookmyshow.com/movies") == []
    # Short brand names only match a whole name, never inside another word.
    assert piracy.inspect("https://ytstudio.example.com/") == []
    assert piracy.inspect("https://www.myyts.com/") == []
    assert piracy.inspect("https://yts.mx/")[0]["code"] == "piracy_site"
