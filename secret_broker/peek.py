"""A Show/Hide toggle for a password box: the human can check what they are typing before they submit it.

Only the browser is involved: the button switches the box between `password` and `text`, nothing is sent and the
broker never fills a password box back in. The button is `hidden` until the script runs, so a page without the
script has no dead control. Shared by the credential entry page and the Credentials tab.
"""

CSS = """
.peek{display:flex;gap:.4rem;align-items:center;flex:1 1 14rem;min-width:0}.peek input{flex:1;min-width:0}
.peek .peekbtn{flex:none;min-height:2.25rem}
"""

JS = r"""
(function(){
  [].forEach.call(document.querySelectorAll('button[data-peek]'),function(b){
    var box=b.parentNode.querySelector('input');if(!box)return;b.hidden=false;
    b.addEventListener('click',function(){var show=box.type==='password';box.type=show?'text':'password';
      b.textContent=show?'Hide':'Show';b.setAttribute('aria-pressed',show?'true':'false');box.focus();});
    if(box.form)box.form.addEventListener('submit',function(){box.type='password';});
  });
})();
"""


def wrap(input_html):
    """`input_html` (one password <input>) with its Show/Hide toggle beside it."""
    return (f"<span class=peek>{input_html}<button type=button class='btn sm peekbtn' data-peek hidden "
            f"aria-pressed=false aria-label='Show or hide what you typed'>Show</button></span>")
