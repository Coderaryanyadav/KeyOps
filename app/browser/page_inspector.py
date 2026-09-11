from typing import Dict, List, Any, Optional
from playwright.async_api import Page, ElementHandle
from pydantic import BaseModel, Field, ConfigDict

class InteractiveElement(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)
    element_id: str
    tag: str
    role: str
    text: str
    name: str = ""
    input_type: str = ""
    autocomplete: str = ""
    placeholder: str = ""
    aria_label: str = ""
    href: str = ""
    element_handle: Optional[Any] = None

class PageInspectionResult(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)
    url: str
    title: str
    headings: List[str] = Field(default_factory=list)
    interactive_elements: List[InteractiveElement] = Field(default_factory=list)
    visible_text_summary: str = ""
    element_map: Dict[str, Any] = Field(default_factory=dict)

class PageInspector:
    """
    Inspects live Playwright page, generates deterministic element IDs (e.g., 'elem_1'),
    and extracts a clean, structured semantic representation for the AI reasoning layer.
    """

    async def inspect_page(self, page: Page) -> PageInspectionResult:
        url = page.url
        title = await page.title()
        
        # 1. Extract headings
        heading_handles = await page.query_selector_all("h1, h2, h3, h4")
        headings = []
        for h in heading_handles:
            txt = (await h.text_content() or "").strip()
            if txt:
                headings.append(txt)

        # 2. Extract interactive elements (buttons, links, inputs)
        interactive_elements: List[InteractiveElement] = []
        element_map: Dict[str, ElementHandle] = {}

        raw_elements = await page.query_selector_all("button, a[href], input, select, [role='button'], [role='link']")
        
        counter = 1
        for el in raw_elements:
            try:
                if not await el.is_visible():
                    continue

                elem_id = f"elem_{counter}"
                tag = (await el.evaluate("e => e.tagName.toLowerCase()")) or ""
                text = (await el.text_content() or "").strip()
                name = (await el.get_attribute("name") or "").strip()
                input_type = (await el.get_attribute("type") or "").strip()
                autocomplete = (await el.get_attribute("autocomplete") or "").strip()
                placeholder = (await el.get_attribute("placeholder") or "").strip()
                aria_label = (await el.get_attribute("aria-label") or "").strip()
                href = (await el.get_attribute("href") or "").strip()
                role = (await el.get_attribute("role") or tag).strip()

                item = InteractiveElement(
                    element_id=elem_id,
                    tag=tag,
                    role=role,
                    text=text[:100],
                    name=name,
                    input_type=input_type,
                    autocomplete=autocomplete,
                    placeholder=placeholder,
                    aria_label=aria_label,
                    href=href,
                    element_handle=el
                )
                interactive_elements.append(item)
                element_map[elem_id] = el
                counter += 1
            except Exception:
                continue

        # 3. Extract text summary
        body_text = (await page.inner_text("body") if await page.query_selector("body") else "")[:2000]

        return PageInspectionResult(
            url=url,
            title=title,
            headings=headings,
            interactive_elements=interactive_elements,
            visible_text_summary=body_text,
            element_map=element_map
        )
