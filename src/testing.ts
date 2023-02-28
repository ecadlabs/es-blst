export interface Context {
    title?: string[];
    status?: boolean;
}

export async function run(title: string | null, cb: (ctx: Context) => Promise<void>, context?: Context): Promise<boolean> {
    context = context != null ? context : { status: true };

    const ctx = {
        title: title !== null
            ? [...(context.title != null ? context.title : []), title]
            : context.title != null
                ? [...context.title, "<unnamed>"]
                : undefined,
        status: true
    };
    let error: Error | undefined;
    try {
        await cb(ctx);
    } catch (err) {
        if (err instanceof Error) {
            error = err;
        }
        ctx.status = false;
    }

    if (!ctx.status) {
        context.status = false;
    }

    if (ctx.title != null) {
        console.log(`* ${ctx.title.join("/")}: ${ctx.status ? "ok" : "fail"}`);
    } else {
        console.log(`All: ${ctx.status ? "ok" : "fail"}`);
    }
    if (error != null) {
        console.log("Error message:");
        console.log(error.stack != null ? error.stack : error.message);
    }

    return context.status !== undefined ? context.status : true;
}
