defmodule Wall3t.Automation.Retry do
  @moduledoc "Deterministic exponential backoff with a hard attempt ceiling."

  @spec delay_ms(pos_integer(), keyword()) :: non_neg_integer()
  def delay_ms(attempt, opts \\ []) when is_integer(attempt) and attempt >= 1 do
    base = Keyword.get(opts, :base_ms, 250)
    max_delay = Keyword.get(opts, :max_ms, 30_000)
    min(base * Integer.pow(2, attempt - 1), max_delay)
  end

  @spec retry?(pos_integer(), pos_integer()) :: boolean()
  def retry?(attempt, max_attempts) when is_integer(attempt) and is_integer(max_attempts) do
    attempt < max_attempts
  end
end
