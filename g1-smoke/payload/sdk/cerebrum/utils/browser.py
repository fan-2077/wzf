import os
import time
import shutil
import datetime
import io
import urllib.parse
from typing import Optional, Union, Literal, Tuple, List, Dict, Any, BinaryIO
from PIL import Image
from playwright.sync_api import sync_playwright
from typing import TypedDict
import random
from typing import cast
from copy import deepcopy

from PIL import Image, ImageDraw, ImageFont

TOP_NO_LABEL_ZONE = 20


class DOMRectangle(TypedDict):
    x: Union[int, float]
    y: Union[int, float]
    width: Union[int, float]
    height: Union[int, float]
    top: Union[int, float]
    right: Union[int, float]
    bottom: Union[int, float]
    left: Union[int, float]


class VisualViewport(TypedDict):
    height: Union[int, float]
    width: Union[int, float]
    offsetLeft: Union[int, float]
    offsetTop: Union[int, float]
    pageLeft: Union[int, float]
    pageTop: Union[int, float]
    scale: Union[int, float]
    clientWidth: Union[int, float]
    clientHeight: Union[int, float]
    scrollWidth: Union[int, float]
    scrollHeight: Union[int, float]


class InteractiveRegion(TypedDict):
    tag_name: str
    role: str
    aria_name: str
    v_scrollable: bool
    rects: List[DOMRectangle]


def _get_str(d: Any, k: str) -> str:
    r"""Safely retrieve a string value from a dictionary."""
    if k not in d:
        raise KeyError(f"Missing required key: '{k}'")
    val = d[k]
    if isinstance(val, str):
        return val
    raise TypeError(
        f"Expected a string for key '{k}', " f"but got {type(val).__name__}"
    )


def _get_number(d: Any, k: str) -> Union[int, float]:
    r"""Safely retrieve a number (int or float) from a dictionary"""
    val = d[k]
    if isinstance(val, (int, float)):
        return val
    raise TypeError(
        f"Expected a number (int/float) for key "
        f"'{k}', but got {type(val).__name__}"
    )


def _get_bool(d: Any, k: str) -> bool:
    r"""Safely retrieve a boolean value from a dictionary."""
    val = d[k]
    if isinstance(val, bool):
        return val
    raise TypeError(
        f"Expected a boolean for key '{k}', " f"but got {type(val).__name__}"
    )

def _reload_image(image: Image.Image):
    buffer = io.BytesIO()
    image.save(buffer, format="PNG")
    buffer.seek(0)
    return Image.open(buffer)


def dom_rectangle_from_dict(rect: Dict[str, Any]) -> DOMRectangle:
    r"""Create a DOMRectangle object from a dictionary."""
    return DOMRectangle(
        x=_get_number(rect, "x"),
        y=_get_number(rect, "y"),
        width=_get_number(rect, "width"),
        height=_get_number(rect, "height"),
        top=_get_number(rect, "top"),
        right=_get_number(rect, "right"),
        bottom=_get_number(rect, "bottom"),
        left=_get_number(rect, "left"),
    )


def interactive_region_from_dict(region: Dict[str, Any]) -> InteractiveRegion:
    r"""Create an :class:`InteractiveRegion` object from a dictionary."""
    typed_rects: List[DOMRectangle] = []
    for rect in region["rects"]:
        typed_rects.append(dom_rectangle_from_dict(rect))

    return InteractiveRegion(
        tag_name=_get_str(region, "tag_name"),
        role=_get_str(region, "role"),
        aria_name=_get_str(region, "aria-name"),
        v_scrollable=_get_bool(region, "v-scrollable"),
        rects=typed_rects,
    )


def visual_viewport_from_dict(viewport: Dict[str, Any]) -> VisualViewport:
    r"""Create a :class:`VisualViewport` object from a dictionary."""
    return VisualViewport(
        height=_get_number(viewport, "height"),
        width=_get_number(viewport, "width"),
        offsetLeft=_get_number(viewport, "offsetLeft"),
        offsetTop=_get_number(viewport, "offsetTop"),
        pageLeft=_get_number(viewport, "pageLeft"),
        pageTop=_get_number(viewport, "pageTop"),
        scale=_get_number(viewport, "scale"),
        clientWidth=_get_number(viewport, "clientWidth"),
        clientHeight=_get_number(viewport, "clientHeight"),
        scrollWidth=_get_number(viewport, "scrollWidth"),
        scrollHeight=_get_number(viewport, "scrollHeight"),
    )


def add_set_of_mark(
    screenshot: Union[bytes, Image.Image, io.BufferedIOBase],
    ROIs: Dict[str, InteractiveRegion],
) -> Tuple[Image.Image, List[str], List[str], List[str]]:
    if isinstance(screenshot, Image.Image):
        return _add_set_of_mark(screenshot, ROIs)

    if isinstance(screenshot, bytes):
        screenshot = io.BytesIO(screenshot)

    image = Image.open(cast(BinaryIO, screenshot))
    comp, visible_rects, rects_above, rects_below = _add_set_of_mark(
        image, ROIs
    )
    image.close()
    return comp, visible_rects, rects_above, rects_below


def _add_set_of_mark(
    screenshot: Image.Image, ROIs: Dict[str, InteractiveRegion]
) -> Tuple[Image.Image, List[str], List[str], List[str]]:
    r"""Add a set of marks to the screenshot.

    Args:
        screenshot (Image.Image): The screenshot to add marks to.
        ROIs (Dict[str, InteractiveRegion]): The regions to add marks to.

    Returns:
        Tuple[Image.Image, List[str], List[str], List[str]]: A tuple
        containing the screenshot with marked ROIs, ROIs fully within the
        images, ROIs located above the visible area, and ROIs located below
        the visible area.
    """
    visible_rects: List[str] = list()
    rects_above: List[str] = list()  # Scroll up to see
    rects_below: List[str] = list()  # Scroll down to see

    fnt = ImageFont.load_default(14)
    base = screenshot.convert("L").convert("RGBA")
    overlay = Image.new("RGBA", base.size)

    draw = ImageDraw.Draw(overlay)
    for r in ROIs:
        for rect in ROIs[r]["rects"]:
            # Empty rectangles
            if not rect or rect["width"] == 0 or rect["height"] == 0:
                continue

            # TODO: add scroll left and right?
            horizontal_center = (rect["right"] + rect["left"]) / 2.0
            vertical_center = (rect["top"] + rect["bottom"]) / 2.0
            is_within_horizon = 0 <= horizontal_center < base.size[0]
            is_above_viewport = vertical_center < 0
            is_below_viewport = vertical_center >= base.size[1]

            if is_within_horizon:
                if is_above_viewport:
                    rects_above.append(r)
                elif is_below_viewport:
                    rects_below.append(r)
                else:  # Fully visible
                    visible_rects.append(r)
                    _draw_roi(draw, int(r), fnt, rect)

    comp = Image.alpha_composite(base, overlay)
    overlay.close()
    return comp, visible_rects, rects_above, rects_below


def _draw_roi(
    draw: ImageDraw.ImageDraw,
    idx: int,
    font: ImageFont.FreeTypeFont | ImageFont.ImageFont,
    rect: DOMRectangle,
) -> None:
    r"""Draw a ROI on the image.

    Args:
        draw (ImageDraw.ImageDraw): The draw object.
        idx (int): The index of the ROI.
        font (ImageFont.FreeTypeFont | ImageFont.ImageFont): The font.
        rect (DOMRectangle): The DOM rectangle.
    """
    color = _get_random_color(idx)
    text_color = _get_text_color(color)

    roi = ((rect["left"], rect["top"]), (rect["right"], rect["bottom"]))

    label_location = (rect["right"], rect["top"])
    label_anchor = "rb"

    if label_location[1] <= TOP_NO_LABEL_ZONE:
        label_location = (rect["right"], rect["bottom"])
        label_anchor = "rt"

    draw.rectangle(
        roi, outline=color, fill=(color[0], color[1], color[2], 48), width=2
    )

    bbox = draw.textbbox(
        label_location,
        str(idx),
        font=font,
        anchor=label_anchor,
        align="center",
    )
    bbox = (bbox[0] - 3, bbox[1] - 3, bbox[2] + 3, bbox[3] + 3)
    draw.rectangle(bbox, fill=color)

    draw.text(
        label_location,
        str(idx),
        fill=text_color,
        font=font,
        anchor=label_anchor,
        align="center",
    )


def _get_text_color(
    bg_color: Tuple[int, int, int, int],
) -> Tuple[int, int, int, int]:
    r"""Determine the ideal text color (black or white) for contrast.

    Args:
        bg_color: The background color (R, G, B, A).

    Returns:
        A tuple representing black or white color for text.
    """
    luminance = bg_color[0] * 0.3 + bg_color[1] * 0.59 + bg_color[2] * 0.11
    return (0, 0, 0, 255) if luminance > 120 else (255, 255, 255, 255)


def _get_random_color(identifier: int) -> Tuple[int, int, int, int]:
    r"""Generate a consistent random RGBA color based on the identifier.

    Args:
        identifier: The ID used as a seed to ensure color consistency.

    Returns:
        A tuple representing (R, G, B, A) values.
    """
    rnd = random.Random(int(identifier))
    r = rnd.randint(0, 255)
    g = rnd.randint(125, 255)
    b = rnd.randint(0, 50)
    color = [r, g, b]
    # TODO: check why shuffle is needed?
    rnd.shuffle(color)
    color.append(255)
    return cast(Tuple[int, int, int, int], tuple(color))

class BaseBrowser:
    def __init__(
        self,
        headless=True,
        cache_dir: Optional[str] = None,
        channel: Literal["chrome", "msedge", "chromium"] = "chromium",
    ):
        r"""Initialize the WebBrowser instance.

        Args:
            headless (bool): Whether to run the browser in headless mode.
            cache_dir (Union[str, None]): The directory to store cache files.
            channel (Literal["chrome", "msedge", "chromium"]): The browser
                channel to use. Must be one of "chrome", "msedge", or
                "chromium".

        Returns:
            None
        """

        self.history: list = []
        self.headless = headless
        self.channel = channel
        self._ensure_browser_installed()
        self.playwright = sync_playwright().start()
        self.page_history: list = []  # stores the history of visited pages

        # Set the cache directory
        self.cache_dir = "tmp/" if cache_dir is None else cache_dir
        os.makedirs(self.cache_dir, exist_ok=True)

        # Load the page script
        abs_dir_path = os.path.dirname(os.path.abspath(__file__))
        page_script_path = os.path.join(abs_dir_path, "page_script.js")

        try:
            with open(page_script_path, "r", encoding='utf-8') as f:
                self.page_script = f.read()
            f.close()
        except FileNotFoundError:
            raise FileNotFoundError(
                f"Page script file not found at path: {page_script_path}"
            )

    def init(self) -> None:
        r"""Initialize the browser."""
        # Launch the browser, if headless is False, the browser will display
        self.browser = self.playwright.chromium.launch(
            headless=self.headless, channel=self.channel
        )
        # Create a new context
        self.context = self.browser.new_context(accept_downloads=True)
        # Create a new page
        self.page = self.context.new_page()

    def clean_cache(self) -> None:
        r"""Delete the cache directory and its contents."""
        if os.path.exists(self.cache_dir):
            shutil.rmtree(self.cache_dir)

    def _wait_for_load(self, timeout: int = 20) -> None:
        r"""Wait for a certain amount of time for the page to load."""
        timeout_ms = timeout * 1000

        self.page.wait_for_load_state("load", timeout=timeout_ms)

        # TODO: check if this is needed
        time.sleep(2)

    def click_blank_area(self) -> None:
        r"""Click a blank area of the page to unfocus the current element."""
        self.page.mouse.click(0, 0)
        self._wait_for_load()

    def visit_page(self, url: str) -> None:
        r"""Visit a page with the given URL."""

        self.page.goto(url)
        self._wait_for_load()
        self.page_url = url

    # def ask_question_about_video(self, question: str) -> str:
    #     r"""Ask a question about the video on the current page,
    #     such as YouTube video.

    #     Args:
    #         question (str): The question to ask.

    #     Returns:
    #         str: The answer to the question.
    #     """
    #     video_analyzer = VideoAnalysisToolkit()
    #     result = video_analyzer.ask_question_about_video(
    #         self.page_url, question
    #     )
    #     return result

    # @retry_on_error()
    def get_screenshot(
        self, save_image: bool = False
    ) -> Tuple[Image.Image, Union[str, None]]:
        r"""Get a screenshot of the current page.

        Args:
            save_image (bool): Whether to save the image to the cache
                directory.

        Returns:
            Tuple[Image.Image, str]: A tuple containing the screenshot
            image and the path to the image file if saved, otherwise
            :obj:`None`.
        """

        image_data = self.page.screenshot(timeout=60000)
        image = Image.open(io.BytesIO(image_data))

        file_path = None
        if save_image:
            # Get url name to form a file name
            # Use urlparser for a safer extraction the url name
            parsed_url = urllib.parse.urlparse(self.page_url)
            url_name = os.path.basename(str(parsed_url.path)) or "index"

            for char in ['\\', '/', ':', '*', '?', '"', '<', '>', '|', '.']:
                url_name = url_name.replace(char, "_")

            # Get formatted time: mmddhhmmss
            timestamp = datetime.datetime.now().strftime("%m%d%H%M%S")
            file_path = os.path.join(
                self.cache_dir, f"{url_name}_{timestamp}.png"
            )
            with open(file_path, "wb") as f:
                image.save(f, "PNG")
            f.close()

        return image, file_path

    def capture_full_page_screenshots(
        self, scroll_ratio: float = 0.8
    ) -> List[str]:
        r"""Capture full page screenshots by scrolling the page with a buffer
        zone.

        Args:
            scroll_ratio (float): The ratio of viewport height to scroll each
                step. (default: :obj:`0.8`)

        Returns:
            List[str]: A list of paths to the screenshot files.
        """
        screenshots = []
        scroll_height = self.page.evaluate("document.body.scrollHeight")
        assert self.page.viewport_size is not None
        viewport_height = self.page.viewport_size["height"]
        current_scroll = 0
        screenshot_index = 1

        max_height = scroll_height - viewport_height
        scroll_step = int(viewport_height * scroll_ratio)

        last_height = 0

        while True:
            # print(
            #     f"Current scroll: {current_scroll}, max_height: "
            #     f"{max_height}, step: {scroll_step}"
            # )

            _, file_path = self.get_screenshot(save_image=True)
            screenshots.append(file_path)

            self.page.evaluate(f"window.scrollBy(0, {scroll_step})")
            # Allow time for content to load
            time.sleep(0.5)

            current_scroll = self.page.evaluate("window.scrollY")
            # Break if there is no significant scroll
            if abs(current_scroll - last_height) < viewport_height * 0.1:
                break

            last_height = current_scroll
            screenshot_index += 1

        return screenshots

    def get_visual_viewport(self) -> VisualViewport:
        r"""Get the visual viewport of the current page.

        Returns:
            VisualViewport: The visual viewport of the current page.
        """
        try:
            self.page.evaluate(self.page_script)
        except Exception as e:
            pass
            # print(f"Error evaluating page script: {e}")

        return visual_viewport_from_dict(
            self.page.evaluate("MultimodalWebSurfer.getVisualViewport();")
        )

    def get_interactive_elements(self) -> Dict[str, InteractiveRegion]:
        r"""Get the interactive elements of the current page.

        Returns:
            Dict[str, InteractiveRegion]: A dictionary of interactive elements.
        """
        try:
            self.page.evaluate(self.page_script)
        except Exception as e:
            print(f"Error evaluating page script: {e}")

        result = cast(
            Dict[str, Dict[str, Any]],
            self.page.evaluate("MultimodalWebSurfer.getInteractiveRects();"),
        )

        typed_results: Dict[str, InteractiveRegion] = {}
        for k in result:
            typed_results[k] = interactive_region_from_dict(result[k])

        return typed_results  # type: ignore[return-value]

    def get_som_screenshot(
        self,
        save_image: bool = False,
    ) -> Tuple[Image.Image, Union[str, None]]:
        r"""Get a screenshot of the current viewport with interactive elements
        marked.

        Args:
            save_image (bool): Whether to save the image to the cache
                directory.

        Returns:
            Tuple[Image.Image, str]: A tuple containing the screenshot image
                and the path to the image file.
        """

        self._wait_for_load()
        screenshot, _ = self.get_screenshot(save_image=save_image)
        rects = self.get_interactive_elements()

        file_path = None
        comp, visible_rects, rects_above, rects_below = add_set_of_mark(
            screenshot,
            rects,  # type: ignore[arg-type]
        )
        if save_image:
            parsed_url = urllib.parse.urlparse(self.page_url)
            url_name = os.path.basename(str(parsed_url.path)) or "index"
            for char in ['\\', '/', ':', '*', '?', '"', '<', '>', '|', '.']:
                url_name = url_name.replace(char, "_")
            timestamp = datetime.datetime.now().strftime("%m%d%H%M%S")
            file_path = os.path.join(
                self.cache_dir, f"{url_name}_{timestamp}.png"
            )
            with open(file_path, "wb") as f:
                comp.save(f, "PNG")
            f.close()

        return comp, file_path

    def scroll_up(self) -> None:
        r"""Scroll up the page."""
        self.page.keyboard.press("PageUp")

    def scroll_down(self) -> None:
        r"""Scroll down the page."""
        self.page.keyboard.press("PageDown")

    def get_url(self) -> str:
        r"""Get the URL of the current page."""
        return self.page.url

    def click_id(self, identifier: Union[str, int]) -> None:
        r"""Click an element with the given identifier."""
        if isinstance(identifier, int):
            identifier = str(identifier)
        target = self.page.locator(f"[__elementId='{identifier}']")

        try:
            target.wait_for(timeout=5000)
        except (TimeoutError, Exception) as e:
            print(f"Error during click operation: {e}")
            raise ValueError("No such element.") from None

        target.scroll_into_view_if_needed()

        new_page = None
        try:
            with self.page.expect_event("popup", timeout=1000) as page_info:
                box = cast(Dict[str, Union[int, float]], target.bounding_box())
                self.page.mouse.click(
                    box["x"] + box["width"] / 2, box["y"] + box["height"] / 2
                )
                new_page = page_info.value

                # If a new page is opened, switch to it
                if new_page:
                    self.page_history.append(deepcopy(self.page.url))
                    self.page = new_page

        except (TimeoutError, Exception) as e:
            print(f"Error during click operation: {e}")
            pass

        self._wait_for_load()

    def extract_url_content(self) -> str:
        r"""Extract the content of the current page."""
        content = self.page.content()
        return content

    def download_file_id(self, identifier: Union[str, int]) -> str:
        r"""Download a file with the given selector.

        Args:
            identifier (str): The identifier of the file to download.
            file_path (str): The path to save the downloaded file.

        Returns:
            str: The result of the action.
        """

        if isinstance(identifier, int):
            identifier = str(identifier)
        try:
            target = self.page.locator(f"[__elementId='{identifier}']")
        except (TimeoutError, Exception) as e:
            print(f"Error during download operation: {e}")
            print(
                f"Element with identifier '{identifier}' not found."
            )
            return f"Element with identifier '{identifier}' not found."

        target.scroll_into_view_if_needed()

        file_path = os.path.join(self.cache_dir)
        self._wait_for_load()

        try:
            with self.page.expect_download() as download_info:
                target.click()
                download = download_info.value
                file_name = download.suggested_filename

                file_path = os.path.join(file_path, file_name)
                download.save_as(file_path)

            return f"Downloaded file to path '{file_path}'."

        except (TimeoutError, Exception) as e:
            print(f"Error during download operation: {e}")
            return f"Failed to download file with identifier '{identifier}'."

    def fill_input_id(self, identifier: Union[str, int], text: str) -> str:
        r"""Fill an input field with the given text, and then press Enter.

        Args:
            identifier (str): The identifier of the input field.
            text (str): The text to fill.

        Returns:
            str: The result of the action.
        """
        if isinstance(identifier, int):
            identifier = str(identifier)

        try:
            target = self.page.locator(f"[__elementId='{identifier}']")
        except (TimeoutError, Exception) as e:
            print(f"Error during fill operation: {e}")
            print(
                f"Element with identifier '{identifier}' not found."
            )
            return f"Element with identifier '{identifier}' not found."

        target.scroll_into_view_if_needed()
        target.focus()
        try:
            target.fill(text)
        except (TimeoutError, Exception) as e:
            print(f"Error during fill operation: {e}")
            target.press_sequentially(text)

        target.press("Enter")
        self._wait_for_load()
        return (
            f"Filled input field '{identifier}' with text '{text}' "
            f"and pressed Enter."
        )

    def scroll_to_bottom(self) -> str:
        self.page.evaluate("window.scrollTo(0, document.body.scrollHeight);")
        self._wait_for_load()
        return "Scrolled to the bottom of the page."

    def scroll_to_top(self) -> str:
        self.page.evaluate("window.scrollTo(0, 0);")
        self._wait_for_load()
        return "Scrolled to the top of the page."

    def hover_id(self, identifier: Union[str, int]) -> str:
        r"""Hover over an element with the given identifier.

        Args:
            identifier (str): The identifier of the element to hover over.

        Returns:
            str: The result of the action.
        """
        if isinstance(identifier, int):
            identifier = str(identifier)
        try:
            target = self.page.locator(f"[__elementId='{identifier}']")
        except (TimeoutError, Exception) as e:
            print(f"Error during hover operation: {e}")
            print(
                f"Element with identifier '{identifier}' not found."
            )
            return f"Element with identifier '{identifier}' not found."

        target.scroll_into_view_if_needed()
        target.hover()
        self._wait_for_load()
        return f"Hovered over element with identifier '{identifier}'."

    def find_text_on_page(self, search_text: str) -> str:
        r"""Find the next given text on the page, and scroll the page to the
        targeted text. It is equivalent to pressing Ctrl + F and searching for
        the text.
        """
        # ruff: noqa: E501
        script = f"""
        (function() {{
            let text = "{search_text}";
            let found = window.find(text);
            if (!found) {{
                let elements = document.querySelectorAll("*:not(script):not(style)"); 
                for (let el of elements) {{
                    if (el.innerText && el.innerText.includes(text)) {{
                        el.scrollIntoView({{behavior: "smooth", block: "center"}});
                        el.style.backgroundColor = "yellow";
                        el.style.border = '2px solid red';
                        return true;
                    }}
                }}
                return false;
            }}
            return true;
        }})();
        """
        found = self.page.evaluate(script)
        self._wait_for_load()
        if found:
            return f"Found text '{search_text}' on the page."
        else:
            return f"Text '{search_text}' not found on the page."

    def back(self):
        r"""Navigate back to the previous page."""

        page_url_before = self.page.url
        self.page.go_back()

        page_url_after = self.page.url

        if page_url_after == "about:blank":
            self.visit_page(page_url_before)

        if page_url_before == page_url_after:
            # If the page is not changed, try to use the history
            if len(self.page_history) > 0:
                self.visit_page(self.page_history.pop())

        time.sleep(1)
        self._wait_for_load()

    def close(self):
        self.browser.close()

    # ruff: noqa: E501
    def show_interactive_elements(self):
        r"""Show simple interactive elements on the current page."""
        self.page.evaluate(self.page_script)
        self.page.evaluate("""
        () => {
            document.querySelectorAll('a, button, input, select, textarea, [tabindex]:not([tabindex="-1"]), [contenteditable="true"]').forEach(el => {
                el.style.border = '2px solid red';
            });
            }
        """)

    # @retry_on_error()
    def get_webpage_content(self) -> str:
        from html2text import html2text

        self._wait_for_load()
        html_content = self.page.content()

        markdown_content = html2text(html_content)
        return markdown_content

    def _ensure_browser_installed(self) -> None:
        r"""Ensure the browser is installed."""
        import platform
        import subprocess
        import sys

        try:
            from playwright.sync_api import sync_playwright

            with sync_playwright() as p:
                browser = p.chromium.launch(channel=self.channel)
                browser.close()
        except Exception:
            print("Installing Chromium browser...")
            try:
                subprocess.run(
                    [
                        sys.executable,
                        "-m",
                        "playwright",
                        "install",
                        self.channel,
                    ],
                    check=True,
                    capture_output=True,
                )
                if platform.system().lower() == "linux":
                    subprocess.run(
                        [
                            sys.executable,
                            "-m",
                            "playwright",
                            "install-deps",
                            self.channel,
                        ],
                        check=True,
                        capture_output=True,
                    )
                print("Chromium browser installation completed")
            except subprocess.CalledProcessError as e:
                raise RuntimeError(f"Failed to install browser: {e.stderr}")

