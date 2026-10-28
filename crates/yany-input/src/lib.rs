use yany_core::input::InputEvent;
use yany_core::YanyError;

#[cfg(windows)]
use windows::Win32::UI::Input::KeyboardAndMouse::{
    SendInput, INPUT, INPUT_0, INPUT_KEYBOARD, INPUT_MOUSE, KEYBDINPUT, KEYEVENTF_KEYUP,
    MOUSEEVENTF_ABSOLUTE, MOUSEEVENTF_LEFTDOWN, MOUSEEVENTF_LEFTUP, MOUSEEVENTF_MIDDLEDOWN,
    MOUSEEVENTF_MIDDLEUP, MOUSEEVENTF_MOVE, MOUSEEVENTF_RIGHTDOWN, MOUSEEVENTF_RIGHTUP,
    MOUSEEVENTF_WHEEL, MOUSEINPUT, VIRTUAL_KEY,
};

pub fn inject(events: &[InputEvent]) -> Result<(), YanyError> {
    if events.len() > 64 {
        return Err(YanyError::Invalid("too many input events".into()));
    }
    #[cfg(windows)]
    {
        unsafe { inject_windows(events) }
    }
    #[cfg(not(windows))]
    {
        let _ = events;
        Err(YanyError::Invalid("input injection is Windows-only".into()))
    }
}

#[cfg(windows)]
unsafe fn inject_windows(events: &[InputEvent]) -> Result<(), YanyError> {
    let mut packed: Vec<INPUT> = Vec::with_capacity(events.len());
    for ev in events {
        packed.push(match ev {
            InputEvent::MouseMove { x, y } => mouse_move(*x, *y),
            InputEvent::MouseButton { button, down } => mouse_button(*button, *down),
            InputEvent::MouseWheel { delta } => mouse_wheel(*delta),
            InputEvent::Key { vk, down, scan } => key(*vk, *down, *scan),
        });
    }
    let sent = SendInput(&packed, std::mem::size_of::<INPUT>() as i32);
    if sent as usize != packed.len() {
        return Err(YanyError::Invalid("SendInput incomplete".into()));
    }
    Ok(())
}

#[cfg(windows)]
fn mouse_move(x: u16, y: u16) -> INPUT {
    INPUT {
        r#type: INPUT_MOUSE,
        Anonymous: INPUT_0 {
            mi: MOUSEINPUT {
                dx: x as i32,
                dy: y as i32,
                mouseData: 0,
                dwFlags: MOUSEEVENTF_MOVE | MOUSEEVENTF_ABSOLUTE,
                time: 0,
                dwExtraInfo: 0,
            },
        },
    }
}

#[cfg(windows)]
fn mouse_button(button: u8, down: bool) -> INPUT {
    let flags = match (button, down) {
        (0, true) => MOUSEEVENTF_LEFTDOWN,
        (0, false) => MOUSEEVENTF_LEFTUP,
        (1, true) => MOUSEEVENTF_RIGHTDOWN,
        (1, false) => MOUSEEVENTF_RIGHTUP,
        (_, true) => MOUSEEVENTF_MIDDLEDOWN,
        (_, false) => MOUSEEVENTF_MIDDLEUP,
    };
    INPUT {
        r#type: INPUT_MOUSE,
        Anonymous: INPUT_0 {
            mi: MOUSEINPUT {
                dx: 0,
                dy: 0,
                mouseData: 0,
                dwFlags: flags,
                time: 0,
                dwExtraInfo: 0,
            },
        },
    }
}

#[cfg(windows)]
fn mouse_wheel(delta: i16) -> INPUT {
    INPUT {
        r#type: INPUT_MOUSE,
        Anonymous: INPUT_0 {
            mi: MOUSEINPUT {
                dx: 0,
                dy: 0,
                mouseData: delta as i32 as u32,
                dwFlags: MOUSEEVENTF_WHEEL,
                time: 0,
                dwExtraInfo: 0,
            },
        },
    }
}

#[cfg(windows)]
fn key(vk: u16, down: bool, scan: u16) -> INPUT {
    let mut flags = windows::Win32::UI::Input::KeyboardAndMouse::KEYBD_EVENT_FLAGS(0);
    if !down {
        flags |= KEYEVENTF_KEYUP;
    }
    INPUT {
        r#type: INPUT_KEYBOARD,
        Anonymous: INPUT_0 {
            ki: KEYBDINPUT {
                wVk: VIRTUAL_KEY(vk),
                wScan: scan,
                dwFlags: flags,
                time: 0,
                dwExtraInfo: 0,
            },
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_oversized_batch() {
        let events = vec![InputEvent::MouseMove { x: 0, y: 0 }; 65];
        assert!(inject(&events).is_err());
    }

    #[test]
    fn wheel_keeps_negative_delta() {
        let packed = (-120i16) as i32 as u32;
        assert_eq!(packed as i32, -120);
    }
}
